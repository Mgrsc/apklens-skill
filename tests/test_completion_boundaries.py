import copy
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from support import make_apk, make_dex

from scripts.static_analysis import binary, engine, storage
from scripts.static_analysis.common import (
    MEMORY_BUDGET_MESSAGE,
    AnalysisError,
    Budget,
    BudgetExceeded,
    Limits,
    MemoryBudgetExceeded,
    snapshot_file,
    stage,
)
from scripts.static_analysis.storage import AnalysisStore, checkpoint_source

ROOT = Path(__file__).resolve().parents[1]
SIGNAL_RECORDS = 513
MAX_SIGNAL_RECORDS_AFTER_STOP = 256


class CompletionBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()

    def artifact(self, name="input", prior_failure=False):
        entries = {"res/bad.xml": b"invalid"} if prior_failure else {}
        entries["classes.dex"] = make_dex(url="https://errors.sentry.io/events")
        return snapshot_file(
            make_apk(self.root / f"{name}.apk", entries=entries),
            self.root / "artifacts",
            self.limits,
            threading.Event(),
        )

    def store(self, name):
        store = AnalysisStore(self.root / f"{name}.sqlite3")
        self.addCleanup(store.close)
        return store

    def test_dex_signal_stops_preserve_facts_and_checkpoint_retry_policy(self):
        artifact = self.artifact()
        for mode in ("quick", "standard", "decompile"):
            for phase in ("dex_method_id", "dex_invocation"):
                if phase == "dex_invocation" and mode == "quick":
                    continue
                index = binary.dex_index(
                    make_dex(url="https://errors.sentry.io/events"),
                    self.limits,
                    Budget(self.limits),
                    inspect_code=mode != "quick",
                )
                if phase == "dex_method_id":
                    index["methods"] = [
                        index["methods"][ordinal % len(index["methods"])]
                        for ordinal in range(SIGNAL_RECORDS)
                    ]
                else:
                    index["calls"] = [
                        {**index["calls"][0], "instruction_offset": ordinal}
                        for ordinal in range(SIGNAL_RECORDS)
                    ]
                with patch.object(engine, "dex_index", return_value=index):
                    expected = engine.analyze_artifact(
                        artifact, self.limits, mode, threading.Event()
                    )
                for stop in ("cancel", "timeout", "memory"):
                    with self.subTest(mode=mode, phase=phase, stop=stop):
                        cancel = threading.Event()
                        state = {"seen": 0, "requested": False, "raised": False}
                        original_matches = engine.signal_matches
                        error = (
                            BudgetExceeded("Artifact time budget exceeded")
                            if stop == "timeout"
                            else MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE)
                            if stop == "memory"
                            else None
                        )

                        class InterruptedBudget(Budget):
                            def check(self, state=state, error=error):
                                if state["requested"] and error and not state["raised"]:
                                    state["raised"] = True
                                    raise error
                                super().check()

                        def observed(
                            value,
                            source,
                            level="E1",
                            phase=phase,
                            state=state,
                            stop=stop,
                            cancel=cancel,
                            original_matches=original_matches,
                        ):
                            if source["kind"] == phase:
                                state["seen"] += 1
                                if state["seen"] == 5:
                                    state["requested"] = True
                                    if stop == "cancel":
                                        cancel.set()
                            return original_matches(value, source, level)

                        source = self.store(f"source-{mode}-{phase}-{stop}")
                        events = []
                        with (
                            patch.object(engine, "dex_index", return_value=index),
                            patch.object(
                                engine, "signal_matches", side_effect=observed
                            ),
                            patch.object(engine, "Budget", InterruptedBudget),
                        ):
                            results = engine.analyze_many(
                                [artifact],
                                self.limits,
                                mode,
                                cancel,
                                1,
                                None,
                                events.append,
                                store=source,
                            )
                        parsed = results[artifact["sha256"]]
                        self.assertTrue(state["requested"])
                        self.assertLessEqual(
                            state["seen"] - 5, MAX_SIGNAL_RECORDS_AFTER_STOP
                        )
                        self.assertEqual(parsed["manifest"], expected["manifest"])
                        self.assertEqual(
                            list(parsed["endpoints"]), expected["endpoints"]
                        )
                        self.assertTrue(list(parsed["signals"]))
                        self.assertEqual(
                            bool(parsed.get("resource_limited")), stop == "memory"
                        )
                        self.assertEqual(cancel.is_set(), stop != "timeout")
                        self.assertEqual(
                            events[-1]["status"],
                            "CANCELLED" if stop == "cancel" else "PARTIAL",
                        )
                        key = engine.cache_key(artifact["sha256"], self.limits, mode)
                        self.assertEqual(
                            source.reusable(artifact["sha256"], key, False),
                            stop == "timeout",
                        )
                        self.assertFalse(source.reusable(artifact["sha256"], key, True))
                        before = source.path.read_bytes()
                        for retry in (False, True):
                            target = self.store(f"target-{mode}-{phase}-{stop}-{retry}")
                            with (
                                patch.object(engine, "dex_index", return_value=index),
                                patch.object(
                                    engine,
                                    "analyze_artifact",
                                    wraps=engine.analyze_artifact,
                                ) as parser,
                            ):
                                recovered = engine.analyze_many(
                                    [artifact],
                                    self.limits,
                                    mode,
                                    threading.Event(),
                                    1,
                                    None,
                                    lambda event: None,
                                    store=target,
                                    resume_store=source,
                                    retry_incomplete=retry,
                                )
                            reparsed = stop != "timeout" or retry
                            self.assertEqual(parser.call_count, int(reparsed))
                            if reparsed:
                                for section in ("endpoints", "signals", "sdks"):
                                    self.assertEqual(
                                        list(recovered[artifact["sha256"]][section]),
                                        expected[section],
                                    )
                            self.assertEqual(source.path.read_bytes(), before)

    def test_last_dex_signal_cancellation_is_independent_of_cache(self):
        for mode in ("quick", "standard", "decompile"):
            for cache_mode in ("disabled", "admission_skipped", "prior_failure"):
                artifact = self.artifact(
                    f"{mode}-{cache_mode}", cache_mode == "prior_failure"
                )
                directory = (
                    None
                    if cache_mode == "disabled"
                    else self.root / f"cache-{mode}-{cache_mode}"
                )
                expected = engine.analyze_artifact(
                    artifact, self.limits, mode, threading.Event(), directory
                )
                cache_file = (
                    directory / f"{expected['cache_key']}.json" if directory else None
                )
                before = (
                    cache_file.read_bytes()
                    if cache_file and cache_file.exists()
                    else None
                )
                for phase in ("dex_method_id", "dex_invocation"):
                    if mode == "quick" and phase == "dex_invocation":
                        continue
                    with self.subTest(mode=mode, cache=cache_mode, phase=phase):
                        cancel = threading.Event()
                        original_matches = engine.signal_matches

                        def observed(
                            value,
                            source,
                            level="E1",
                            phase=phase,
                            cancel=cancel,
                            original_matches=original_matches,
                        ):
                            if source["kind"] == phase and (
                                phase != "dex_method_id" or source["method_index"] == 1
                            ):
                                cancel.set()
                            return original_matches(value, source, level)

                        with (
                            patch.object(engine, "cache_read", return_value=None),
                            patch.object(
                                engine, "signal_matches", side_effect=observed
                            ),
                            patch.object(engine, "cache_write") as writer,
                        ):
                            parsed = engine.analyze_artifact(
                                artifact, self.limits, mode, cancel, directory
                            )
                        self.assertTrue(cancel.is_set())
                        self.assertEqual(storage.artifact_status(parsed), "CANCELLED")
                        self.assertEqual(parsed["manifest"], expected["manifest"])
                        self.assertEqual(parsed["endpoints"], expected["endpoints"])
                        writer.assert_not_called()
                        source = self.store(f"last-{mode}-{cache_mode}-{phase}")
                        source.save_artifact(artifact["sha256"], parsed)
                        for retry in (False, True):
                            self.assertFalse(
                                source.reusable(
                                    artifact["sha256"], expected["cache_key"], retry
                                )
                            )
                        if before is not None:
                            self.assertEqual(cache_file.read_bytes(), before)

    def test_cancellation_between_extraction_and_sdk_matching_is_recorded(self):
        artifact = self.artifact()
        original_results = engine.EndpointCollector.results
        for mode in ("quick", "standard", "decompile"):
            with self.subTest(mode=mode):
                cancel = threading.Event()

                def interrupted(collector, cancel=cancel):
                    values = original_results(collector)
                    cancel.set()
                    return values

                with patch.object(engine.EndpointCollector, "results", interrupted):
                    parsed = engine.analyze_artifact(
                        artifact, self.limits, mode, cancel
                    )
                self.assertTrue(parsed["endpoints"])
                self.assertEqual(parsed["sdks"], [])
                self.assertEqual(storage.artifact_status(parsed), "CANCELLED")

    def test_sdk_completion_checks_cancellation_timeout_and_memory(self):
        artifact = self.artifact()
        expected = engine.analyze_artifact(
            artifact, self.limits, "standard", threading.Event()
        )
        for stop in ("cancel", "timeout", "memory"):
            with self.subTest(stop=stop):
                cancel = threading.Event()
                state = {"requested": False, "raised": False}
                error = (
                    BudgetExceeded("Artifact time budget exceeded")
                    if stop == "timeout"
                    else MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE)
                    if stop == "memory"
                    else None
                )
                original_sdk_matches = engine.sdk_matches

                class InterruptedBudget(Budget):
                    def check(self, state=state, error=error):
                        if state["requested"] and error and not state["raised"]:
                            state["raised"] = True
                            raise error
                        super().check()

                def interrupted(
                    *args,
                    original_sdk_matches=original_sdk_matches,
                    state=state,
                    stop=stop,
                    cancel=cancel,
                    **kwargs,
                ):
                    values = original_sdk_matches(*args, **kwargs)
                    state["requested"] = True
                    if stop == "cancel":
                        cancel.set()
                    return values

                with (
                    patch.object(engine, "Budget", InterruptedBudget),
                    patch.object(engine, "sdk_matches", side_effect=interrupted),
                ):
                    parsed = engine.analyze_artifact(
                        artifact, self.limits, "standard", cancel
                    )
                self.assertTrue(state["requested"])
                self.assertEqual(parsed["sdks"], expected["sdks"])
                self.assertEqual(
                    storage.artifact_status(parsed),
                    "CANCELLED" if stop == "cancel" else "PARTIAL",
                )
                self.assertEqual(bool(parsed.get("resource_limited")), stop == "memory")

    def test_cli_cancelled_final_dex_retries_and_restores_sdks(self):
        artifact = self.artifact()
        output = self.root / "interrupted"
        code = """
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
import analyze
from static_analysis import engine
original_parser = engine.analyze_artifact
original_matches = engine.signal_matches
def interrupted(artifact, limits, mode, cancel, cache_directory=None):
    def observed(value, source, level="E1"):
        if source["kind"] == "dex_method_id":
            cancel.set()
        return original_matches(value, source, level)
    with patch.object(engine, "signal_matches", side_effect=observed):
        return original_parser(artifact, limits, mode, cancel, cache_directory)
args = analyze.build_parser().parse_args(["scan", "--apk", sys.argv[2], "--output", sys.argv[3], "--no-cache", "--quiet"])
with patch.object(engine, "analyze_artifact", side_effect=interrupted):
    result = analyze.scan(args)
raise SystemExit(result)
"""
        interrupted = subprocess.run(
            [sys.executable, "-c", code, str(ROOT), artifact["path"], str(output)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(interrupted.returncode, 130, interrupted.stderr)
        self.assertEqual(json.loads(interrupted.stdout)["status"], "CANCELLED")
        source = AnalysisStore(output / "analysis.sqlite3", readonly=True)
        self.addCleanup(source.close)
        self.assertEqual(
            storage.artifact_status(source.artifact(artifact["sha256"])), "CANCELLED"
        )
        source_bytes = source.path.read_bytes()
        expected = engine.analyze_artifact(
            artifact, self.limits, "standard", threading.Event()
        )
        for retry in (False, True):
            destination = self.root / f"resumed-{retry}"
            arguments = [
                sys.executable,
                str(ROOT / "scripts/analyze.py"),
                "scan",
                "--resume",
                str(output),
                "--output",
                str(destination),
                "--no-cache",
                "--quiet",
            ]
            if retry:
                arguments.append("--retry-incomplete")
            resumed = subprocess.run(
                arguments, capture_output=True, text=True, timeout=30, check=False
            )
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            store = AnalysisStore(destination / "analysis.sqlite3", readonly=True)
            self.addCleanup(store.close)
            self.assertEqual(
                list(store.artifact(artifact["sha256"])["sdks"]), expected["sdks"]
            )
            self.assertEqual(source.path.read_bytes(), source_bytes)

    def test_snapshot_reparses_previously_misclassified_complete_checkpoint(self):
        artifact = self.artifact()
        source = self.root / "legacy"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/analyze.py"),
                "scan",
                "--apk",
                artifact["path"],
                "--output",
                str(source),
                "--no-cache",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        store = AnalysisStore(source / "analysis.sqlite3")
        result = store.artifact(artifact["sha256"])
        expected_sdks = list(result["sdks"])
        legacy = {
            key: list(value)
            if key in storage.ARTIFACT_SECTIONS
            else copy.deepcopy(value)
            for key, value in result.items()
        }
        legacy["sdks"] = []
        store.save_artifact(artifact["sha256"], legacy)
        self.assertTrue(store.reusable(artifact["sha256"], legacy["cache_key"], True))
        store.close()
        before = (source / "analysis.sqlite3").read_bytes()
        destination = self.root / "reparsed"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/analyze.py"),
                "scan",
                "--snapshot",
                str(source / "snapshot.json"),
                "--output",
                str(destination),
                "--no-cache",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        store = AnalysisStore(destination / "analysis.sqlite3", readonly=True)
        self.addCleanup(store.close)
        self.assertEqual(
            list(store.artifact(artifact["sha256"])["sdks"]), expected_sdks
        )
        self.assertEqual((source / "analysis.sqlite3").read_bytes(), before)


class LegacyConnection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, *args, **kwargs):
        try:
            return self.connection.execute(*args, **kwargs)
        except sqlite3.Error as error:
            for name in ("sqlite_errorcode", "sqlite_errorname"):
                if hasattr(error, name):
                    delattr(error, name)
            raise

    def __getattr__(self, name):
        return getattr(self.connection, name)


class CheckpointCompatibilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.legacy_sqlite = SimpleNamespace(**vars(sqlite3))
        self.legacy_sqlite.__dict__.pop("SQLITE_READONLY", None)
        self.legacy_sqlite.connect = lambda *args, **kwargs: LegacyConnection(
            sqlite3.connect(*args, **kwargs)
        )

    def checkpoint(self, hot=False):
        path = self.root / "analysis.sqlite3"
        store = AnalysisStore(path)
        store.save_artifact(
            "saved",
            {
                "sha256": "saved",
                "manifest": None,
                "endpoints": [],
                "signals": [],
                "sdks": [],
                "stages": [stage("artifact_analysis")],
                "cache": {"hit": False},
            },
        )
        store.close()
        if hot:
            code = "import os, sqlite3, sys; connection=sqlite3.connect(sys.argv[1]); connection.execute('PRAGMA cache_size=1'); connection.execute('BEGIN IMMEDIATE'); connection.execute(\"INSERT INTO metadata VALUES ('interrupted',?)\", ('x'*50000,)); os._exit(9)"
            interrupted = subprocess.run(
                [sys.executable, "-c", code, str(path)], check=False
            )
            self.assertEqual(interrupted.returncode, 9)
        return path

    def test_legacy_hot_journal_recovery_preserves_source(self):
        path = self.checkpoint(hot=True)
        journal = Path(str(path) + "-journal")
        before = [
            hashlib.sha256(item.read_bytes()).hexdigest() for item in (path, journal)
        ]
        with (
            patch.object(storage, "sqlite3", self.legacy_sqlite),
            checkpoint_source(path, self.root) as recovered,
        ):
            self.assertEqual(recovered.artifact("saved")["sha256"], "saved")
            self.assertIsNone(recovered.metadata("interrupted"))
        self.assertEqual(
            before,
            [hashlib.sha256(item.read_bytes()).hexdigest() for item in (path, journal)],
        )
        self.assertFalse(list(self.root.glob(".recovery-*")))

    def test_legacy_valid_checkpoint_needs_no_recovery(self):
        path = self.checkpoint()
        before = path.read_bytes()
        with (
            patch.object(storage, "sqlite3", self.legacy_sqlite),
            patch.object(
                storage.tempfile,
                "TemporaryDirectory",
                side_effect=AssertionError("Unexpected recovery"),
            ),
            checkpoint_source(path, self.root) as source,
        ):
            self.assertEqual(source.artifact("saved")["sha256"], "saved")
        self.assertEqual(path.read_bytes(), before)

    def test_errors_without_journal_preserve_controlled_failure(self):
        for name in ("missing", "invalid"):
            with self.subTest(name=name):
                path = self.root / f"{name}.sqlite3"
                if name == "invalid":
                    path.write_bytes(b"not a database")
                with (
                    patch.object(storage, "sqlite3", self.legacy_sqlite),
                    patch.object(
                        storage.tempfile,
                        "TemporaryDirectory",
                        side_effect=AssertionError("Unexpected recovery"),
                    ),
                    self.assertRaises(AnalysisError),
                    checkpoint_source(path, self.root),
                ):
                    self.fail("Invalid source opened")
                self.assertEqual(path.exists(), name == "invalid")
                if path.exists():
                    self.assertEqual(path.read_bytes(), b"not a database")

    def test_legacy_corrupt_source_with_journal_cleans_failed_recovery(self):
        path = self.root / "invalid.sqlite3"
        journal = Path(str(path) + "-journal")
        path.write_bytes(b"not a database")
        journal.write_bytes(b"not a journal")
        before = [item.read_bytes() for item in (path, journal)]
        with (
            patch.object(storage, "sqlite3", self.legacy_sqlite),
            self.assertRaises((AnalysisError, sqlite3.Error)),
            checkpoint_source(path, self.root),
        ):
            self.fail("Corrupt source opened")
        self.assertEqual([item.read_bytes() for item in (path, journal)], before)
        self.assertFalse(list(self.root.glob(".recovery-*")))

    @unittest.skipUnless(
        hasattr(sqlite3, "SQLITE_READONLY"), "Requires SQLite error metadata"
    )
    def test_modern_nonreadonly_error_does_not_attempt_recovery(self):
        path = self.root / "invalid.sqlite3"
        journal = Path(str(path) + "-journal")
        path.write_bytes(b"not a database")
        journal.write_bytes(b"\x00" * 512)
        with (
            patch.object(
                storage.tempfile,
                "TemporaryDirectory",
                side_effect=AssertionError("Unexpected recovery"),
            ),
            self.assertRaises(AnalysisError),
            checkpoint_source(path, self.root),
        ):
            self.fail("Corrupt source opened")


if __name__ == "__main__":
    unittest.main()
