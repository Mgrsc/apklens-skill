import ctypes
import json
import multiprocessing
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from support import make_apk, make_dex

from scripts.static_analysis import workers
from scripts.static_analysis.common import (
    AnalysisError,
    Limits,
    MemoryBudgetExceeded,
    TaskBudget,
    process_tree_rss,
    snapshot_file,
)
from scripts.static_analysis.engine import analyze_many
from scripts.static_analysis.metrics import PerformanceMetrics
from scripts.static_analysis.storage import ARTIFACT_SECTIONS, AnalysisStore

ROOT = Path(__file__).resolve().parents[1]
TEST_BLOCK_SECONDS = 60


def without_elapsed(value):
    if isinstance(value, dict):
        return {
            key: without_elapsed(item)
            for key, item in value.items()
            if key != "elapsed_seconds"
        }
    if isinstance(value, list):
        return [without_elapsed(item) for item in value]
    return value


def crash_worker(connection, *arguments):
    connection.send({"event": "ready"})
    try:
        connection.recv()
    except EOFError:
        return
    os._exit(7)


def stuck_worker(connection, *arguments):
    connection.send({"event": "ready"})
    connection.recv()
    time.sleep(TEST_BLOCK_SECONDS)


def unready_worker(connection, *arguments):
    time.sleep(TEST_BLOCK_SECONDS)


def persisting_stalled_worker(connection, *arguments):
    connection.send({"event": "ready"})
    command = connection.recv()
    connection.send({"event": "parsed", "artifact": command["artifact"]["sha256"]})
    time.sleep(TEST_BLOCK_SECONDS)


def resource_limited_worker(*arguments):
    from scripts.static_analysis import engine

    def limited_artifact(artifact, limits, mode, cancel, cache_directory):
        return engine.artifact_failure(
            artifact, MemoryBudgetExceeded("Synthetic worker memory limit")
        ), None

    engine.timed_artifact = limited_artifact
    workers.worker_main(*arguments)


def invalid_worker(connection, *arguments):
    connection.send({"event": "ready"})
    command = connection.recv()
    connection.send(
        {
            "event": "result",
            "artifact": command["artifact"]["sha256"],
            "token": "foreign",
        }
    )
    time.sleep(TEST_BLOCK_SECONDS)


def native_stalled_worker(
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
    workers.arm_parent_death(parent_pid)
    connection.send({"event": "ready"})
    connection.recv()
    (Path(directory) / "native-ready").write_text("ready")
    ctypes.PyDLL(None).sleep(TEST_BLOCK_SECONDS)


@unittest.skipUnless(sys.platform == "linux", "Process executor requires Linux")
class ProcessExecutorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()
        self.artifacts = [
            snapshot_file(
                make_apk(
                    self.root / f"input-{index}.apk",
                    entries={
                        "classes.dex": make_dex(url=f"https://example.org/{index}")
                    },
                ),
                self.root / "artifacts",
                self.limits,
                self.cancel,
            )
            for index in range(3)
        ]

    def store(self, name):
        store = AnalysisStore(self.root / name / "analysis.sqlite3", cancel=self.cancel)
        self.addCleanup(store.close)
        return store

    def run_process(self, store, **kwargs):
        return analyze_many(
            self.artifacts,
            self.limits,
            "standard",
            self.cancel,
            2,
            None,
            lambda event: None,
            store=store,
            executor_kind="process",
            **kwargs,
        )

    def assert_workers_closed(self):
        self.assertEqual(multiprocessing.active_children(), [])
        self.assertFalse(list(self.root.glob("*/.workers-*")))

    def test_process_results_match_threads_and_resume_without_reparse(self):
        thread = self.store("thread")
        process = self.store("process")
        analyze_many(
            self.artifacts,
            self.limits,
            "standard",
            self.cancel,
            2,
            None,
            lambda event: None,
            store=thread,
        )
        metrics = PerformanceMetrics(self.root, "parse")
        try:
            self.run_process(process, metrics=metrics)
        finally:
            metrics.close("COMPLETE")
        self.assertEqual(metrics.runtime["worker_processes_started"], 2)
        for artifact in self.artifacts:
            identity = artifact["sha256"]
            for section in ARTIFACT_SECTIONS:
                self.assertEqual(
                    without_elapsed(list(thread.artifact(identity)[section])),
                    without_elapsed(list(process.artifact(identity)[section])),
                    section,
                )
        resumed = self.store("resumed")
        for artifact in self.artifacts:
            process.update_artifact_metadata(
                artifact["sha256"], {"cache": {"hit": True}}
            )
        process.connection.commit()
        resume_metrics = PerformanceMetrics(self.root, "resume")
        with patch.object(
            workers.multiprocessing,
            "get_context",
            side_effect=AssertionError("Fully resumed tasks must not spawn workers"),
        ):
            try:
                self.run_process(resumed, resume_store=process, metrics=resume_metrics)
            finally:
                resume_metrics.close("COMPLETE")
        self.assertEqual(resume_metrics.runtime["worker_processes_started"], 0)
        self.assertEqual(resume_metrics.counters["checkpoint_reused"], 3)
        self.assertEqual(resume_metrics.counters["cache_hits"], 0)
        self.assertEqual(
            len(list(resumed.connection.execute("SELECT identity FROM artifacts"))), 3
        )
        self.assert_workers_closed()

    def test_worker_crash_invalid_protocol_and_hang_stop_without_leaks(self):
        for index, target in enumerate((crash_worker, invalid_worker, stuck_worker)):
            with self.subTest(target=target.__name__):
                self.cancel.clear()
                store = self.store(str(index))
                self.limits = replace(self.limits, timeout=0.1)
                started = time.monotonic()
                with (
                    patch.object(workers, "worker_main", target),
                    patch.object(workers, "SHUTDOWN_SECONDS", 0.2),
                    self.assertRaises(AnalysisError),
                ):
                    self.run_process(store)
                self.assertLess(time.monotonic() - started, 5)
                self.assertTrue(self.cancel.is_set())
                self.assertEqual(
                    store.connection.execute("PRAGMA integrity_check").fetchone()[0],
                    "ok",
                )
                self.assert_workers_closed()

    def test_import_failure_preserves_committed_results_and_stops_workers(self):
        store = self.store("failure")
        original = store.import_artifact
        imported = []

        def import_result(source, identity, **kwargs):
            if imported:
                raise OSError("Synthetic persistence failure")
            original(source, identity, **kwargs)
            imported.append(identity)

        with (
            patch.object(store, "import_artifact", side_effect=import_result),
            self.assertRaisesRegex(OSError, "Synthetic persistence failure"),
        ):
            self.run_process(store)
        self.assertEqual(
            [
                row[0]
                for row in store.connection.execute("SELECT identity FROM artifacts")
            ],
            imported,
        )
        self.assert_workers_closed()

    def test_resource_limited_result_stops_dispatch_without_worker_stop_signal(self):
        store = self.store("resource-limited")
        store.budget = TaskBudget(self.limits, self.cancel, process_tree=True)
        events = []
        with patch.object(workers, "worker_main", resource_limited_worker):
            results = analyze_many(
                self.artifacts,
                self.limits,
                "standard",
                self.cancel,
                1,
                None,
                events.append,
                store=store,
                executor_kind="process",
            )
        self.assertTrue(self.cancel.is_set())
        self.assertTrue(store.budget.memory_exceeded)
        self.assertEqual(len(events), 1)
        limited = [value for value in results.values() if value.get("resource_limited")]
        self.assertEqual(len(limited), 1)
        unstarted = [
            value for value in results.values() if not value.get("resource_limited")
        ]
        self.assertEqual(len(unstarted), 2)
        for result in unstarted:
            stopped = next(iter(result["stages"]))
            self.assertEqual(stopped["status"], "CANCELLED")
            self.assertEqual(stopped["reason"], "Artifact was not started")
        self.assertEqual(
            store.connection.execute("PRAGMA quick_check").fetchone()[0], "ok"
        )
        self.assert_workers_closed()

    def test_cleanup_preserves_success_and_existing_stop_reasons(self):
        context = multiprocessing.get_context("spawn")
        for value in (
            workers.STOP_NONE,
            workers.STOP_CANCELLED,
            workers.STOP_MEMORY,
            workers.STOP_DISK,
            workers.STOP_FAILED,
        ):
            with self.subTest(reason=value):
                event = context.Event()
                reason = context.Value("i", value)
                workers.stop_workers([], event, reason)
                self.assertTrue(event.is_set())
                self.assertEqual(reason.value, value)

    def test_worker_deadline_errors_identify_phase_and_timeout(self):
        for state, target, timeout in (
            ("starting", unready_worker, "0.5"),
            ("parsing", stuck_worker, "0.3"),
            ("persisting", persisting_stalled_worker, "0.1"),
        ):
            with self.subTest(state=state):
                self.cancel.clear()
                store = self.store(f"deadline-{state}")
                self.limits = replace(self.limits, timeout=0.1)
                with (
                    patch.object(workers, "worker_main", target),
                    patch.object(workers, "STARTUP_SECONDS", 0.5),
                    patch.object(workers, "RESULT_IDLE_SECONDS", 0.1),
                    patch.object(workers, "SHUTDOWN_SECONDS", 0.2),
                    self.assertRaises(AnalysisError) as error,
                ):
                    self.run_process(store)
                self.assertIn(f"phase={state}", str(error.exception))
                self.assertIn(
                    f"response_timeout_seconds={timeout}", str(error.exception)
                )
                self.assert_workers_closed()

    def test_cancellation_stops_active_worker_and_marks_unstarted_artifacts(self):
        store = self.store("cancelled")
        timer = threading.Timer(0.4, self.cancel.set)
        timer.start()
        try:
            with (
                patch.object(workers, "worker_main", stuck_worker),
                patch.object(workers, "SHUTDOWN_SECONDS", 0.2),
            ):
                results = self.run_process(store)
        finally:
            timer.cancel()
            timer.join()
        self.assertEqual(len(results), 3)
        for identity in results:
            self.assertEqual(
                next(iter(results[identity]["stages"]))["status"], "CANCELLED"
            )
        self.assert_workers_closed()

    def test_task_tree_budget_includes_child_resident_memory(self):
        budget = TaskBudget(
            replace(self.limits, memory_bytes=100), self.cancel, process_tree=True
        )
        with (
            patch("scripts.static_analysis.common.resident_bytes", return_value=1),
            patch("scripts.static_analysis.common.process_tree_rss", return_value=101),
            self.assertRaises(MemoryBudgetExceeded),
        ):
            budget.check()
        self.assertTrue(budget.memory_exceeded)
        self.assertTrue(self.cancel.is_set())

    def test_process_budget_is_checked_before_worker_creation(self):
        store = self.store("preflight")
        store.budget = TaskBudget(
            replace(self.limits, memory_bytes=1), self.cancel, process_tree=True
        )
        with (
            patch.object(
                workers.multiprocessing,
                "get_context",
                side_effect=AssertionError(
                    "Memory-limited task must not spawn workers"
                ),
            ),
            self.assertRaises(MemoryBudgetExceeded),
        ):
            self.run_process(store)
        self.assertTrue(store.budget.memory_exceeded)
        self.assert_workers_closed()

    def test_tree_sampler_sees_children_created_by_a_secondary_thread(self):
        baseline = process_tree_rss()
        ready = threading.Event()
        release = threading.Event()
        children = []

        def own_child():
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import time; data = bytearray(32 * 1024 * 1024); print('ready', flush=True); time.sleep(20)",
                ],
                stdout=subprocess.PIPE,
                text=True,
            )
            children.append(child)
            child.stdout.readline()
            ready.set()
            release.wait(5)
            child.terminate()
            child.wait(timeout=5)
            child.stdout.close()

        owner = threading.Thread(target=own_child)
        owner.start()
        try:
            self.assertTrue(ready.wait(5))
            self.assertGreater(process_tree_rss(), baseline + 24 * 1024 * 1024)
        finally:
            release.set()
            owner.join(6)
        self.assertFalse(owner.is_alive())

    def test_worker_exits_when_its_parent_is_killed(self):
        self.check_parent_death(False)

    def test_parent_death_signal_stops_a_native_call_holding_the_gil(self):
        self.check_parent_death(True)

    def check_parent_death(self, native):
        harness = self.root / "parent.py"
        fifo = self.root / "blocked.apk"
        os.mkfifo(fifo)
        harness.write_text(
            "\n".join(
                [
                    "import sys, threading",
                    f"sys.path.insert(0, {str(ROOT)!r})",
                    f"sys.path.insert(0, {str(ROOT / 'tests')!r})",
                    "from scripts.static_analysis.common import Limits",
                    "from scripts.static_analysis.engine import analyze_many",
                    "from scripts.static_analysis.storage import AnalysisStore",
                    "from scripts.static_analysis import workers",
                    "from test_process_executor import native_stalled_worker",
                    "if __name__ == '__main__':",
                    f"    if {native!r}: workers.worker_main = native_stalled_worker",
                    f"    store = AnalysisStore({str(self.root / 'orphan' / 'analysis.sqlite3')!r})",
                    f"    artifact = {{'sha256': 'orphan', 'size': 0, 'path': {str(fifo)!r}}}",
                    "    analyze_many([artifact], Limits(), 'standard', threading.Event(), 1, None, lambda event: None, store=store, executor_kind='process')",
                ]
            )
        )
        parent = subprocess.Popen(
            [sys.executable, str(harness)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        children = []
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                child_ids = (
                    Path(f"/proc/{parent.pid}/task/{parent.pid}/children")
                    .read_text()
                    .split()
                )
                children = [
                    int(pid)
                    for pid in child_ids
                    if b"spawn_main" in Path(f"/proc/{pid}/cmdline").read_bytes()
                ]
                if children:
                    break
                time.sleep(0.05)
            self.assertEqual(len(children), 1)
            if native:
                deadline = time.monotonic() + 5
                while (
                    not list(self.root.glob("orphan/.workers-*/0/native-ready"))
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.05)
                self.assertTrue(
                    list(self.root.glob("orphan/.workers-*/0/native-ready"))
                )
                time.sleep(0.1)
                self.assertIsNone(parent.poll())
                self.assertNotEqual(
                    Path(f"/proc/{children[0]}/stat").read_text().split()[2], "Z"
                )
            else:
                time.sleep(0.2)
            parent.kill()
            parent.communicate(timeout=5)
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                alive = []
                for pid in children:
                    try:
                        if Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z":
                            alive.append(pid)
                    except FileNotFoundError:
                        pass
                if not alive:
                    break
                time.sleep(0.05)
            self.assertEqual(alive, [])
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.communicate(timeout=5)
            for pid in children:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_cli_process_mode_and_old_snapshot_default(self):
        output = self.root / "cli"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/analyze.py"),
                "scan",
                "--apk",
                self.artifacts[0]["path"],
                "--output",
                str(output),
                "--executor",
                "process",
                "--no-cache",
                "--quiet",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            json.loads((output / "snapshot.json").read_text())["configuration"][
                "executor"
            ],
            "process",
        )
        self.assertEqual(
            json.loads((output / "performance.json").read_text())["configuration"][
                "executor"
            ],
            "process",
        )
        snapshot = json.loads((output / "snapshot.json").read_text())
        snapshot["configuration"].pop("executor")
        saved = self.root / "old.json"
        saved.write_text(json.dumps(snapshot))
        resumed = self.root / "old-cli"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/analyze.py"),
                "scan",
                "--snapshot",
                str(saved),
                "--output",
                str(resumed),
                "--no-cache",
                "--quiet",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            json.loads((resumed / "snapshot.json").read_text())["configuration"][
                "executor"
            ],
            "thread",
        )
