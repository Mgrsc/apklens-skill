import contextlib
import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from support import make_apk, make_dex

from scripts.static_analysis import binary, common, engine, reports
from scripts.static_analysis.common import (
    MEMORY_BUDGET_MESSAGE,
    AnalysisError,
    Budget,
    BudgetExceeded,
    Cancelled,
    Limits,
    MemoryBudgetExceeded,
    TaskBudget,
)
from scripts.static_analysis.storage import AnalysisStore, ArtifactResults

ROOT = Path(__file__).resolve().parents[1]
VARIABLE_WIDTH_INSTRUCTIONS = (0x0012,) + (0x0013, 0) * 4096 + (0x000E,)
MAX_INSTRUCTIONS_BETWEEN_BUDGET_CHECKS = 1024


class ResourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cancel = threading.Event()
        self.limits = Limits()

    def artifact(self):
        return common.snapshot_file(
            make_apk(self.root / "input.apk"),
            self.root / "artifacts",
            self.limits,
            self.cancel,
        )

    def cached_artifact(self):
        artifact = self.artifact()
        directory = self.root / "cache"
        result = engine.analyze_artifact(
            artifact, self.limits, "standard", self.cancel, directory
        )
        path = directory / f"{result['cache_key']}.json"
        self.assertTrue(path.is_file())
        return artifact, directory, path, result

    def test_task_memory_guard_preserves_cancellation_and_ignores_artifact_timeout(
        self,
    ):
        budget = TaskBudget(Limits(timeout=0, memory_bytes=1024), self.cancel)
        with patch.object(common, "resident_bytes", return_value=None):
            budget.check()
        with (
            patch.object(common, "resident_bytes", return_value=1025),
            self.assertRaises(MemoryBudgetExceeded),
        ):
            budget.check()
        self.assertTrue(self.cancel.is_set())
        self.assertTrue(budget.memory_exceeded)
        self.cancel.clear()
        budget = TaskBudget(self.limits, self.cancel)
        self.cancel.set()
        with self.assertRaises(Cancelled):
            budget.check()
        self.assertFalse(budget.memory_exceeded)

    def test_aggregation_memory_stop_rolls_back_current_application_and_projections(
        self,
    ):
        artifact = self.artifact()
        result = engine.analyze_artifact(artifact, self.limits, "standard", self.cancel)
        for phase in ("merge", "projection"):
            with self.subTest(phase=phase):
                cancel = threading.Event()
                exceeded = threading.Event()
                store = AnalysisStore(
                    self.root / f"aggregation-{phase}.sqlite3", cancel=cancel
                )
                self.addCleanup(store.close)
                store.save_artifact(artifact["sha256"], result)
                store.budget = TaskBudget(Limits(memory_bytes=1024), cancel)
                method = "merge" if phase == "merge" else "_insert_evidence_refs"
                original = getattr(store, method)

                def interrupt(*args, original=original, exceeded=exceeded, **kwargs):
                    value = original(*args, **kwargs)
                    exceeded.set()
                    return value

                with (
                    patch.object(
                        common,
                        "resident_bytes",
                        side_effect=lambda exceeded=exceeded: (
                            2048 if exceeded.is_set() else 0
                        ),
                    ),
                    patch.object(store, method, side_effect=interrupt),
                    self.assertRaises(MemoryBudgetExceeded),
                ):
                    engine.build_apps(
                        [artifact],
                        ArtifactResults(store),
                        None,
                        self.limits,
                        "standard",
                        store=store,
                    )
                self.assertTrue(store.budget.memory_exceeded)
                self.assertTrue(cancel.is_set())
                self.assertEqual(
                    store.connection.execute("SELECT COUNT(*) FROM apps").fetchone()[0],
                    0,
                )
                self.assertEqual(
                    store.connection.execute(
                        "SELECT COUNT(*) FROM records WHERE scope='app'"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    store.connection.execute(
                        "SELECT COUNT(*) FROM evidence_refs"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    store.connection.execute("SELECT COUNT(*) FROM domains").fetchone()[
                        0
                    ],
                    0,
                )
                self.assertEqual(
                    store.connection.execute(
                        "SELECT COUNT(*) FROM metadata WHERE key LIKE 'app_view:%'"
                    ).fetchone()[0],
                    0,
                )
                self.assertTrue(
                    store.reusable(
                        artifact["sha256"],
                        engine.cache_key(artifact["sha256"], self.limits, "standard"),
                        False,
                    )
                )

    def test_export_memory_stop_preserves_current_file_and_committed_report(self):
        from benchmarks.performance import build_fixture

        store, report, _ = build_fixture(self.root, 1, 8)
        self.addCleanup(store.close)
        store.cancel = None
        native = json.loads("".join(common.json_chunks(report)))
        original_writer = common.atomic_writer
        filenames = (
            "analysis.json",
            "summary.json",
            "report.md",
            "domains.txt",
            "telemetry-domains.txt",
        )
        for source_index, source in enumerate((report, native)):
            for filename in filenames:
                with self.subTest(source=source_index, filename=filename):
                    cancel = threading.Event()
                    exceeded = threading.Event()
                    budget = TaskBudget(Limits(memory_bytes=1024), cancel)
                    output = self.root / f"memory-{source_index}-{filename}"
                    output.mkdir()
                    target = output / filename
                    target.write_text("original", encoding="utf-8")

                    @contextlib.contextmanager
                    def writer(path, filename=filename, exceeded=exceeded, **options):
                        if Path(path).name == filename:
                            exceeded.set()
                        with original_writer(path, **options) as handle:
                            yield handle

                    with (
                        patch.object(
                            common,
                            "resident_bytes",
                            side_effect=lambda exceeded=exceeded: (
                                2048 if exceeded.is_set() else 0
                            ),
                        ),
                        patch.object(common, "atomic_writer", writer),
                        patch.object(reports, "atomic_writer", writer),
                        self.assertRaises(MemoryBudgetExceeded),
                    ):
                        reports.export_reports(
                            source, output, cancel=cancel, budget=budget
                        )
                    self.assertTrue(budget.memory_exceeded)
                    self.assertTrue(cancel.is_set())
                    self.assertEqual(target.read_text(), "original")
                    self.assertTrue(
                        all(path.name in filenames for path in output.iterdir())
                    )
        loaded = reports.load_report(store.path)
        self.addCleanup(reports.close_report, loaded)
        self.assertEqual(reports.query(loaded, "endpoints")["total"], 8)

    def test_cli_memory_stop_after_parsing_preserves_reusable_checkpoints(self):
        apk = make_apk(self.root / "input.apk")
        program = """
import contextlib
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import analyze
from static_analysis import common, reports
exceeded = False
resident = common.resident_bytes
common.resident_bytes = lambda: 1024 ** 4 if exceeded else resident()
phase = sys.argv[4]
if phase == "aggregation":
    original = analyze.build_apps
    def aggregate(*args, **options):
        global exceeded
        exceeded = True
        return original(*args, **options)
    analyze.build_apps = aggregate
else:
    original = analyze.export_reports
    def export(*args, **options):
        global exceeded
        if phase == "domains":
            original_writer = reports.atomic_writer
            @contextlib.contextmanager
            def writer(path, **settings):
                global exceeded
                if Path(path).name == "domains.txt":
                    exceeded = True
                with original_writer(path, **settings) as handle:
                    yield handle
            reports.atomic_writer = writer
        files = original(*args, **options)
        exceeded = True
        return files
    analyze.export_reports = export
args = analyze.build_parser().parse_args(["scan", "--apk", sys.argv[2], "--output", sys.argv[3], "--memory-mib", "512", "--no-cache", "--quiet"])
raise SystemExit(analyze.scan(args))
"""
        for phase in ("aggregation", "domains", "after-export"):
            with self.subTest(phase=phase):
                output = self.root / phase
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        program,
                        str(ROOT / "scripts"),
                        str(apk),
                        str(output),
                        phase,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(completed.returncode, 130, completed.stderr)
                payload = json.loads(completed.stdout)
                self.assertEqual(payload["status"], "CANCELLED")
                self.assertEqual(payload["stop_reason"], "memory_budget")
                progress = json.loads((output / "progress.json").read_text())
                self.assertEqual(progress["event"], "interrupted")
                self.assertEqual(progress["stop_reason"], "memory_budget")
                store = AnalysisStore(output / "analysis.sqlite3", readonly=True)
                try:
                    for identity in ArtifactResults(store):
                        result = store.artifact(identity)
                        self.assertFalse(result.get("resource_limited", False))
                        self.assertTrue(
                            store.reusable(identity, result["cache_key"], False)
                        )
                    if phase != "aggregation":
                        self.assertGreater(
                            reports.query(store.report(), "endpoints")["total"], 0
                        )
                finally:
                    store.close()
                resumed = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts/analyze.py"),
                        "scan",
                        "--resume",
                        str(output),
                        "--memory-mib",
                        "512",
                        "--no-cache",
                        "--output",
                        str(self.root / f"resumed-{phase}"),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                events = [json.loads(line) for line in resumed.stderr.splitlines()]
                self.assertTrue(
                    next(
                        event
                        for event in events
                        if event["event"] == "analysis.artifact_completed"
                    )["resumed"]
                )

    def test_atomic_outputs_cancel_before_replacing_existing_file(self):
        for writer, value in (
            (common.atomic_text, "replacement"),
            (common.atomic_json, {"new": True}),
        ):
            with self.subTest(writer=writer.__name__):
                self.cancel.clear()
                path = self.root / "output.json"
                path.write_text("original", encoding="utf-8")
                with (
                    patch.object(
                        common.os,
                        "fsync",
                        side_effect=lambda descriptor: self.cancel.set(),
                    ),
                    self.assertRaises(Cancelled),
                ):
                    writer(path, value, cancel=self.cancel)
                self.assertEqual(path.read_text(), "original")
                self.assertEqual(list(self.root.iterdir()), [path])

    def test_pre_cancelled_cache_write_does_not_hash_or_replace(self):
        path = self.root / "cache.json"
        path.write_text("original", encoding="utf-8")
        self.cancel.set()
        with (
            patch.object(
                engine, "json_checksum", wraps=common.json_checksum
            ) as checksum,
            self.assertRaises(Cancelled),
        ):
            engine.cache_write(path, {"stages": []}, self.cancel)
        checksum.assert_not_called()
        self.assertEqual(path.read_text(), "original")

    def test_pre_cancelled_cache_read_does_not_load_or_hash(self):
        _, _, path, _ = self.cached_artifact()
        self.cancel.set()
        with (
            patch.object(engine, "read_json", wraps=common.read_json) as reader,
            patch.object(
                engine, "json_checksum", wraps=common.json_checksum
            ) as checksum,
            self.assertRaises(Cancelled),
        ):
            engine.cache_read(path, Budget(self.limits, self.cancel))
        reader.assert_not_called()
        checksum.assert_not_called()

    def test_checksum_cancellation_stops_before_encoding_all_records(self):
        original = json.JSONEncoder.iterencode
        observed = []

        def chunks(encoder, value):
            for index, chunk in enumerate(original(encoder, value)):
                observed.append(index)
                if index == 5:
                    self.cancel.set()
                yield chunk

        with (
            patch.object(json.JSONEncoder, "iterencode", chunks),
            self.assertRaises(Cancelled),
        ):
            common.json_checksum(list(range(10000)), cancel=self.cancel)
        self.assertLess(len(observed), 10000)

    def test_checksum_checks_time_and_memory_budgets_during_encoding(self):
        for error in (
            BudgetExceeded("Artifact time budget exceeded"),
            MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE),
        ):
            with self.subTest(error=type(error).__name__):
                budget = SimpleNamespace(
                    check=unittest.mock.Mock(side_effect=[None, None, error])
                )
                with self.assertRaises(type(error)):
                    common.json_checksum(list(range(5000)), budget=budget)
                self.assertEqual(budget.check.call_count, 3)

    def test_json_read_is_chunked_and_cancellable_before_decoding(self):
        path = self.root / "input.json"
        path.write_text(json.dumps({"text": "a" * 256}), encoding="utf-8")
        original_open = Path.open
        sizes = []

        @contextlib.contextmanager
        def opened(path, *args, **options):
            with original_open(path, *args, **options) as handle:

                class Reader:
                    def fileno(self):
                        return handle.fileno()

                    def read(inner, size):
                        sizes.append(size)
                        chunk = handle.read(size)
                        if len(sizes) == 2:
                            self.cancel.set()
                        return chunk

                yield Reader()

        with (
            patch.object(common, "JSON_READ_BYTES", 16),
            patch.object(Path, "open", opened),
            patch.object(common.json, "loads", wraps=json.loads) as decoder,
            self.assertRaises(Cancelled),
        ):
            common.read_json(path, cancel=self.cancel)
        self.assertEqual(sizes, [16, 16])
        decoder.assert_not_called()

    def test_json_read_preserves_encoding_and_enforces_size_limit(self):
        value = {"text": "\U0001f600\u4e2d\x00"}
        for encoding in ("utf-8", "utf-16", "utf-32"):
            with self.subTest(encoding=encoding):
                path = self.root / "input.json"
                data = json.dumps(value, ensure_ascii=False).encode(encoding)
                path.write_bytes(data)
                self.assertEqual(common.read_json(path, max_bytes=len(data)), value)
                with self.assertRaises(AnalysisError):
                    common.read_json(path, max_bytes=len(data) - 1)

    def test_cache_admission_preserves_file_and_reparses_without_replacing_it(self):
        artifact, directory, path, original = self.cached_artifact()
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        with (
            patch.object(engine, "available_memory", return_value=1),
            patch.object(engine, "cache_write", wraps=engine.cache_write) as writer,
        ):
            result = engine.analyze_artifact(
                artifact, self.limits, "standard", self.cancel, directory
            )
        writer.assert_not_called()
        self.assertFalse(result["cache"]["hit"])
        self.assertIn("memory headroom", result["cache"]["notice"])
        self.assertEqual(result["endpoints"], original["endpoints"])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), checksum)

    def test_cache_admission_obeys_remaining_process_budget(self):
        _, _, path, _ = self.cached_artifact()
        budget = Budget(Limits(memory_bytes=path.stat().st_size), self.cancel)
        with (
            patch.object(common, "resident_bytes", return_value=0),
            patch.object(engine, "resident_bytes", return_value=0),
            patch.object(engine, "available_memory", return_value=None),
            patch.object(engine, "read_json", wraps=common.read_json) as reader,
        ):
            self.assertIsNone(engine.cache_read(path, budget))
        reader.assert_not_called()

    def test_cache_read_resource_errors_do_not_fall_back_to_parsing(self):
        artifact, directory, path, _ = self.cached_artifact()
        before = path.read_bytes()
        for error, status in (
            (Cancelled("Cache cancelled"), "CANCELLED"),
            (BudgetExceeded("Cache timeout"), "PARTIAL"),
            (MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE), "PARTIAL"),
        ):
            with self.subTest(error=type(error).__name__):
                self.cancel.clear()
                store = AnalysisStore(
                    self.root / f"read-{status}-{type(error).__name__}.sqlite3"
                )
                self.addCleanup(store.close)
                with (
                    patch.object(engine, "json_checksum", side_effect=error),
                    patch.object(
                        engine,
                        "dex_index",
                        side_effect=AssertionError("Unexpected reparse"),
                    ),
                ):
                    results = engine.analyze_many(
                        [artifact],
                        self.limits,
                        "standard",
                        self.cancel,
                        1,
                        directory,
                        lambda event: None,
                        store=store,
                    )
                result = results[artifact["sha256"]]
                self.assertEqual(result["stages"][0]["status"], status)
                self.assertEqual(
                    bool(result["resource_limited"]),
                    isinstance(error, MemoryBudgetExceeded),
                )
                self.assertFalse(
                    store.reusable(
                        artifact["sha256"],
                        engine.cache_key(artifact["sha256"], self.limits, "standard"),
                        False,
                    )
                )
                self.assertEqual(path.read_bytes(), before)
        self.cancel.clear()
        recovered = engine.analyze_artifact(
            artifact, self.limits, "standard", self.cancel, directory
        )
        self.assertTrue(recovered["cache"]["hit"])

    def test_cache_write_resource_errors_preserve_facts_and_original_file(self):
        artifact = self.artifact()
        result = engine.analyze_artifact(artifact, self.limits, "standard", self.cancel)
        key = result["cache_key"]
        for error, status in (
            (Cancelled("Cache cancelled"), "CANCELLED"),
            (BudgetExceeded("Cache timeout"), "PARTIAL"),
            (MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE), "PARTIAL"),
        ):
            with self.subTest(error=type(error).__name__):
                self.cancel.clear()
                directory = self.root / type(error).__name__
                directory.mkdir()
                path = directory / f"{key}.json"
                path.write_text("original", encoding="utf-8")
                with (
                    patch.object(engine, "json_checksum", side_effect=error),
                    self.assertRaises(type(error)),
                ):
                    engine.cache_write(
                        path, result, self.cancel, Budget(self.limits, self.cancel)
                    )
                self.assertEqual(path.read_text(), "original")
                with patch.object(engine, "cache_write", side_effect=error):
                    parsed = engine.analyze_artifact(
                        artifact,
                        self.limits,
                        "standard",
                        self.cancel,
                        self.root / f"empty-{type(error).__name__}",
                    )
                self.assertEqual(parsed["endpoints"], result["endpoints"])
                self.assertEqual(parsed["stages"][-1]["stage"], "result_cache")
                self.assertEqual(parsed["stages"][-1]["status"], status)
                self.assertEqual(
                    bool(parsed.get("resource_limited")),
                    isinstance(error, MemoryBudgetExceeded),
                )

    def test_domain_cancellation_mid_write_keeps_previous_file(self):
        from benchmarks.performance import build_fixture

        store, report, _ = build_fixture(self.root, 1, 8)
        self.addCleanup(store.close)
        store.cancel = None
        original_writer = common.atomic_writer
        for filename in ("domains.txt", "telemetry-domains.txt"):
            with self.subTest(filename=filename):
                self.cancel.clear()
                output = self.root / filename
                output.mkdir()
                target = output / filename
                target.write_text("original", encoding="utf-8")
                written = []

                @contextlib.contextmanager
                def interrupted_writer(
                    path, target_filename=filename, recorded=written, **options
                ):
                    with original_writer(path, **options) as handle:

                        class Writer:
                            def write(inner, value):
                                result = handle.write(value)
                                if Path(path).name == target_filename:
                                    recorded.append(value)
                                    self.cancel.set()
                                return result

                        yield Writer()

                with (
                    patch.object(reports, "atomic_writer", interrupted_writer),
                    self.assertRaises(Cancelled),
                ):
                    reports.export_reports(report, output, cancel=self.cancel)
                self.assertTrue(written)
                self.assertEqual(target.read_text(), "original")

    def test_export_cancellation_preserves_current_file_at_each_boundary(self):
        from benchmarks.performance import build_fixture

        store, report, _ = build_fixture(self.root, 1, 8)
        self.addCleanup(store.close)
        store.cancel = None
        native = json.loads("".join(common.json_chunks(report)))
        filenames = (
            "analysis.json",
            "summary.json",
            "report.md",
            "domains.txt",
            "telemetry-domains.txt",
        )
        original_writer = common.atomic_writer
        for source_index, source in enumerate((report, native)):
            for filename in filenames:
                with self.subTest(source=source_index, filename=filename):
                    self.cancel.clear()
                    output = self.root / f"output-{source_index}-{filename}"
                    output.mkdir()
                    target = output / filename
                    target.write_text("original", encoding="utf-8")

                    @contextlib.contextmanager
                    def interrupted_writer(path, target_filename=filename, **options):
                        if Path(path).name == target_filename:
                            self.cancel.set()
                        with original_writer(path, **options) as handle:
                            yield handle

                    with (
                        patch.object(common, "atomic_writer", interrupted_writer),
                        patch.object(reports, "atomic_writer", interrupted_writer),
                        self.assertRaises(Cancelled),
                    ):
                        reports.export_reports(source, output, cancel=self.cancel)
                    self.assertEqual(target.read_text(), "original")
                    self.assertTrue(
                        all(path.name in filenames for path in output.iterdir())
                    )

    def test_cli_checks_cancellation_after_export_and_keeps_report_usable(self):
        apk = make_apk(self.root / "input.apk")
        program = """
import contextlib
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import analyze
from static_analysis import reports
from static_analysis.common import atomic_writer
original = analyze.export_reports
def interrupted_export(*args, **options):
    if sys.argv[-1] == "domains":
        @contextlib.contextmanager
        def writer(path, **settings):
            if Path(path).name == "domains.txt":
                options["cancel"].set()
            with atomic_writer(path, **settings) as handle:
                yield handle
        with patch.object(reports, "atomic_writer", writer):
            return original(*args, **options)
    files = original(*args, **options)
    options["cancel"].set()
    return files
analyze.export_reports = interrupted_export
phase = sys.argv[4]
args = analyze.build_parser().parse_args(["scan", "--apk", sys.argv[2], "--output", sys.argv[3], "--no-cache", "--quiet"])
sys.argv = ["analyze.py", phase]
raise SystemExit(analyze.scan(args))
"""
        for phase in ("domains", "after-export"):
            with self.subTest(phase=phase):
                output = self.root / phase
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        program,
                        str(ROOT / "scripts"),
                        str(apk),
                        str(output),
                        phase,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(completed.returncode, 130, completed.stderr)
                self.assertEqual(json.loads(completed.stdout)["status"], "CANCELLED")
                self.assertEqual(
                    json.loads((output / "progress.json").read_text())["event"],
                    "interrupted",
                )
                report = reports.load_report(output / "analysis.sqlite3")
                self.addCleanup(reports.close_report, report)
                self.assertGreater(reports.query(report, "endpoints")["total"], 0)
                files = reports.export_reports(report, self.root / f"reexport-{phase}")
                self.assertTrue(all(Path(path).is_file() for path in files.values()))

    def test_variable_width_dex_checks_budget_during_uninterrupted_scan(self):
        data = make_dex(instructions=VARIABLE_WIDTH_INSTRUCTIONS)
        checkpoints = []
        executed = []
        original_width = binary.instruction_width

        class ObservedBudget(Budget):
            def check(self):
                checkpoints.append(len(executed))
                super().check()

        def observe_width(units, position):
            executed.append(position)
            return original_width(units, position)

        with patch.object(binary, "instruction_width", observe_width):
            result = binary.dex_index(data, self.limits, ObservedBudget(self.limits))
        self.assertEqual(result["scanned_methods"], 1)
        self.assertEqual(result["gaps"], [])
        self.assertEqual(len(executed), 8196)
        checkpoints.append(len(executed))
        self.assertLessEqual(
            max(after - before for before, after in pairwise(checkpoints)),
            MAX_INSTRUCTIONS_BETWEEN_BUDGET_CHECKS,
        )

    def test_variable_width_dex_mid_method_stops_preserve_resume_contract(self):
        data = make_dex(instructions=VARIABLE_WIDTH_INSTRUCTIONS)
        artifact = common.snapshot_file(
            make_apk(self.root / "input.apk", entries={"classes.dex": data}),
            self.root / "artifacts",
            self.limits,
            self.cancel,
        )
        original_width = binary.instruction_width
        for mode in ("standard", "decompile"):
            expected = engine.analyze_artifact(
                artifact, self.limits, mode, threading.Event()
            )
            for stop in ("cancel", "timeout", "memory"):
                with self.subTest(mode=mode, stop=stop):
                    self.cancel.clear()
                    state = {"executed": 0, "requested": False, "raised": False}
                    error = (
                        BudgetExceeded("Artifact time budget exceeded")
                        if stop == "timeout"
                        else MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE)
                        if stop == "memory"
                        else None
                    )

                    class OneShotBudget(Budget):
                        def check(self, state=state, error=error):
                            if state["requested"] and not state["raised"] and error:
                                state["raised"] = True
                                raise error
                            super().check()

                    def request_stop(units, position, state=state, stop=stop):
                        state["executed"] += 1
                        if state["executed"] == 2:
                            state["requested"] = True
                            if stop == "cancel":
                                self.cancel.set()
                        return original_width(units, position)

                    source = AnalysisStore(self.root / f"{mode}-{stop}.sqlite3")
                    self.addCleanup(source.close)
                    events = []
                    with (
                        patch.object(binary, "instruction_width", request_stop),
                        patch.object(engine, "Budget", OneShotBudget),
                    ):
                        results = engine.analyze_many(
                            [artifact],
                            self.limits,
                            mode,
                            self.cancel,
                            1,
                            None,
                            events.append,
                            store=source,
                        )
                    self.assertTrue(state["requested"])
                    self.assertLessEqual(
                        state["executed"] - 1,
                        MAX_INSTRUCTIONS_BETWEEN_BUDGET_CHECKS,
                    )
                    result = results[artifact["sha256"]]
                    self.assertEqual(result["manifest"], expected["manifest"])
                    self.assertEqual(
                        bool(result.get("resource_limited")), stop == "memory"
                    )
                    self.assertEqual(self.cancel.is_set(), stop != "timeout")
                    self.assertEqual(
                        events[-1]["status"],
                        "CANCELLED" if stop == "cancel" else "PARTIAL",
                    )
                    self.assertTrue(events[-1]["persisted"])
                    key = engine.cache_key(artifact["sha256"], self.limits, mode)
                    self.assertEqual(
                        source.reusable(artifact["sha256"], key, False),
                        stop == "timeout",
                    )
                    self.assertFalse(source.reusable(artifact["sha256"], key, True))
                    before = source.path.read_bytes()
                    self.cancel.clear()
                    for retry_incomplete in (False, True):
                        target = AnalysisStore(
                            self.root / f"{mode}-{stop}-{retry_incomplete}.sqlite3"
                        )
                        self.addCleanup(target.close)
                        with patch.object(
                            engine, "analyze_artifact", wraps=engine.analyze_artifact
                        ) as parser:
                            recovered = engine.analyze_many(
                                [artifact],
                                self.limits,
                                mode,
                                self.cancel,
                                1,
                                None,
                                lambda event: None,
                                store=target,
                                resume_store=source,
                                retry_incomplete=retry_incomplete,
                            )
                        reparsed = stop != "timeout" or retry_incomplete
                        self.assertEqual(parser.call_count, int(reparsed))
                        if reparsed:
                            for section in ("endpoints", "signals", "sdks"):
                                self.assertEqual(
                                    list(recovered[artifact["sha256"]][section]),
                                    expected[section],
                                )
                        self.assertEqual(source.path.read_bytes(), before)

    def test_variable_width_dex_quick_mode_keeps_facts_without_scanning_code(self):
        expected = binary.dex_index(
            make_dex(), self.limits, Budget(self.limits), inspect_code=False
        )
        with patch.object(
            binary,
            "instruction_width",
            side_effect=AssertionError("Unexpected instruction scan"),
        ):
            result = binary.dex_index(
                make_dex(instructions=VARIABLE_WIDTH_INSTRUCTIONS),
                self.limits,
                Budget(self.limits),
                inspect_code=False,
            )
        self.assertEqual(result, expected)

    def test_dex_checksums_share_the_original_buffer(self):
        data = make_dex()
        with (
            patch.object(binary.zlib, "adler32", wraps=binary.zlib.adler32) as adler,
            patch.object(binary.hashlib, "sha1", wraps=binary.hashlib.sha1) as sha1,
        ):
            binary.dex_index(data, self.limits, Budget(self.limits))
        for argument in (adler.call_args.args[0], sha1.call_args.args[0]):
            self.assertIsInstance(argument, memoryview)
            self.assertIs(argument.obj, data)


if __name__ == "__main__":
    unittest.main()
