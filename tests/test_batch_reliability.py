import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import weakref
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from support import legacy_store_layout, make_apk, make_dex

from scripts.static_analysis.common import (
    AnalysisError,
    Budget,
    Limits,
    MemoryBudgetExceeded,
    TaskBudget,
    atomic_json,
    available_memory,
    json_checksum,
    json_chunks,
    snapshot_file,
    stage,
)
from scripts.static_analysis.device import DeviceCollector
from scripts.static_analysis.engine import (
    analyze_artifact,
    analyze_many,
    build_apps,
    cache_key,
)
from scripts.static_analysis.reports import (
    SECTIONS,
    close_report,
    export_reports,
    load_report,
    query,
    summary,
)
from scripts.static_analysis.storage import (
    AnalysisStore,
    ArtifactResults,
    artifact_status,
    checkpoint_source,
)
from scripts.static_analysis.tasks import (
    DEFAULT_CONFIGURATION,
    MIB,
    load_snapshot,
    resource_plan,
    save_snapshot,
    verify_artifacts,
)

ROOT = Path(__file__).resolve().parents[1]


class BatchReliabilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()

    def store(self, name):
        store = AnalysisStore(self.root / name)
        self.addCleanup(store.close)
        return store

    def artifact(self, name="input.apk", **options):
        path = make_apk(self.root / name, **options)
        return snapshot_file(path, self.root / "artifacts", self.limits, self.cancel)

    def result(self, identity, status="COMPLETE", **fields):
        return {
            "sha256": identity,
            "manifest": None,
            "cache_key": cache_key(identity, self.limits, "standard"),
            "cache": {"hit": False},
            "statistics": {},
            "endpoints": [],
            "signals": [],
            "sdks": [],
            "stages": [stage("artifact_analysis", status)],
            **fields,
        }

    def cli(self, *arguments):
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "analyze.py"),
                "scan",
                *map(str, arguments),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def report(self, apps):
        return {
            "schema_version": 1,
            "engine_version": "1.0.0",
            "run": {"id": "synthetic-run", "status": "PARTIAL", "mode": "standard"},
            "stages": [],
            "snapshot": None,
            "apps": apps,
            "artifacts": [],
            "totals": {
                "apps": len(apps),
                "artifacts": 2,
                "endpoints": sum(len(app["endpoints"]) for app in apps),
                "findings": sum(len(app["findings"]) for app in apps),
                "cache_hits": 0,
            },
            "limitations": [],
        }

    def test_disk_merge_exports_and_queries_match_legacy_facts(self):
        artifacts = [
            self.artifact(
                "base.apk",
                entries={
                    "classes.dex": make_dex(
                        url="https://errors.sentry.io/events?token=private"
                    )
                },
            ),
            self.artifact(
                "split.apk",
                split="feature",
                entries={
                    "classes.dex": make_dex(
                        url="https://errors.sentry.io/events?token=private"
                    )
                },
            ),
        ]
        results = {
            item["sha256"]: analyze_artifact(item, self.limits, "standard", self.cancel)
            for item in artifacts
        }
        original_results = json.dumps(results, sort_keys=True)
        legacy = self.report(
            build_apps(artifacts, results, None, self.limits, "standard")
        )
        store = self.store("analysis.sqlite3")
        for identity, result in results.items():
            store.save_artifact(identity, result)
        apps = build_apps(
            artifacts,
            ArtifactResults(store),
            None,
            self.limits,
            "standard",
            store=store,
        )
        report = self.report(apps)
        store.save_report(report)
        self.assertEqual(json.loads("".join(json_chunks(report))), legacy)
        self.assertEqual(json.dumps(results, sort_keys=True), original_results)
        self.assertEqual(summary(report), summary(legacy))
        export_reports(report, self.root / "disk")
        export_reports(legacy, self.root / "legacy")
        for filename in (
            "analysis.json",
            "summary.json",
            "report.md",
            "domains.txt",
            "telemetry-domains.txt",
        ):
            disk = (self.root / "disk" / filename).read_bytes()
            legacy_file = (self.root / "legacy" / filename).read_bytes()
            self.assertEqual(
                json.loads(disk) if filename.endswith(".json") else disk,
                json.loads(legacy_file) if filename.endswith(".json") else legacy_file,
                filename,
            )
        with patch(
            "scripts.static_analysis.reports.read_json",
            side_effect=AssertionError("Unexpected whole-file JSON load"),
        ):
            loaded = load_report(store.path)
        self.addCleanup(close_report, loaded)
        for section in SECTIONS:
            for sensitive in (False, True):
                with self.subTest(section=section, sensitive=sensitive):
                    self.assertEqual(
                        query(
                            loaded,
                            section,
                            package="com.example.app",
                            offset=1,
                            limit=2,
                            include_sensitive=sensitive,
                        ),
                        query(
                            legacy,
                            section,
                            package="com.example.app",
                            offset=1,
                            limit=2,
                            include_sensitive=sensitive,
                        ),
                    )

    def test_completed_checkpoints_resume_without_parser_calls(self):
        artifact = self.artifact()
        source = self.store("source.sqlite3")
        result = analyze_artifact(artifact, self.limits, "standard", self.cancel)
        source.save_artifact(artifact["sha256"], result)
        destination = self.store("destination.sqlite3")
        events = []
        with patch(
            "scripts.static_analysis.engine.analyze_artifact",
            side_effect=AssertionError("Checkpoint was reparsed"),
        ):
            results = analyze_many(
                [artifact],
                self.limits,
                "standard",
                self.cancel,
                1,
                None,
                events.append,
                store=destination,
                resume_store=source,
            )
        self.assertEqual(len(results), 1)
        self.assertTrue(events[0]["resumed"])
        self.assertTrue(events[0]["persisted"])
        self.assertEqual(events[0]["complete"], 1)
        self.assertEqual(list(results[artifact["sha256"]]["stages"]), result["stages"])

    def test_resume_retries_failed_cancelled_resource_limited_and_changed_limits(self):
        artifacts = [{"sha256": f"{index:064x}"} for index in range(6)]
        source = self.store("source.sqlite3")
        statuses = ("COMPLETE", "PARTIAL", "FAILED", "CANCELLED", "PARTIAL", "COMPLETE")
        for index, artifact in enumerate(artifacts):
            result = self.result(artifact["sha256"], statuses[index])
            if index == 4:
                result["resource_limited"] = True
            if index == 5:
                result["cache_key"] = cache_key(
                    artifact["sha256"], replace(self.limits, max_results=1), "standard"
                )
            source.save_artifact(artifact["sha256"], result)
        for retry_incomplete in (False, True):
            with self.subTest(retry_incomplete=retry_incomplete):
                destination = self.store(f"destination-{retry_incomplete}.sqlite3")
                with patch(
                    "scripts.static_analysis.engine.analyze_artifact",
                    side_effect=lambda artifact, *args: self.result(artifact["sha256"]),
                ) as parser:
                    analyze_many(
                        artifacts,
                        self.limits,
                        "standard",
                        self.cancel,
                        1,
                        None,
                        lambda event: None,
                        store=destination,
                        resume_store=source,
                        retry_incomplete=retry_incomplete,
                    )
                expected = {
                    artifact["sha256"]
                    for artifact in artifacts[1 if retry_incomplete else 2 :]
                }
                self.assertEqual(
                    {call.args[0]["sha256"] for call in parser.call_args_list}, expected
                )

    def test_streamed_stages_and_imported_checkpoints_preserve_derived_status(self):
        for version in (1, 2):
            source = self.store(f"stage-source-{version}.sqlite3")
            expected_stages = {}
            for status in (
                "COMPLETE",
                "PARTIAL",
                "DEFERRED",
                "UNAVAILABLE",
                "FAILED",
                "CANCELLED",
            ):
                stages = [stage("artifact_analysis", status)]
                for streamed in (False, True):
                    identity = f"{status}-{streamed}"
                    expected_stages[identity] = stages
                    source.save_artifact(
                        identity,
                        self.result(
                            identity, stages=iter(stages) if streamed else stages
                        ),
                    )
            legacy_store_layout(source.connection, version)
            source.connection.commit()
            before = source.path.read_bytes()
            previous = AnalysisStore(source.path, readonly=True)
            self.addCleanup(previous.close)
            for generation in range(2):
                target = self.store(f"stage-target-{version}-{generation}.sqlite3")
                for identity, stages in expected_stages.items():
                    with self.subTest(
                        version=version, generation=generation, identity=identity
                    ):
                        target.import_artifact(previous, identity)
                        expected = stages[0]["status"]
                        if expected in {"DEFERRED", "UNAVAILABLE"}:
                            expected = "PARTIAL"
                        row = target.connection.execute(
                            "SELECT status FROM artifacts WHERE identity=?", (identity,)
                        ).fetchone()
                        self.assertEqual(row[0], expected)
                        self.assertEqual(
                            list(target.artifact(identity)["stages"]), stages
                        )
                        self.assertEqual(
                            artifact_status({"stages": iter(stages)}), expected
                        )
                        self.assertEqual(
                            target.reusable(
                                identity,
                                cache_key(identity, self.limits, "standard"),
                                True,
                            ),
                            expected == "COMPLETE",
                        )
                previous = target
            self.assertEqual(source.path.read_bytes(), before)

    def test_retry_incomplete_reparses_after_an_intermediate_checkpoint_import(self):
        apk = make_apk(
            self.root / "limited.apk",
            entries={
                "assets/urls.txt": "https://one.example.org/a\nhttps://two.example.org/b"
            },
        )
        previous = None
        for generation in range(3):
            output = self.root / f"generation-{generation}"
            arguments = ["--resume", previous] if previous else ["--apk", apk]
            if generation == 2:
                arguments.append("--retry-incomplete")
            before = (
                {
                    name: (previous / name).read_bytes()
                    for name in ("snapshot.json", "analysis.sqlite3")
                }
                if previous
                else {}
            )
            completed = self.cli(
                *arguments,
                "--output",
                output,
                "--max-results",
                "1",
                "--no-cache",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            event = next(
                event
                for line in completed.stderr.splitlines()
                if (event := json.loads(line))["event"] == "analysis.artifact_completed"
            )
            self.assertEqual(event["status"], "PARTIAL")
            self.assertEqual(event["resumed"], generation == 1)
            with closing(sqlite3.connect(output / "analysis.sqlite3")) as connection:
                row = connection.execute("SELECT status FROM artifacts").fetchone()
            self.assertEqual(row[0], "PARTIAL")
            for name, content in before.items():
                self.assertEqual((previous / name).read_bytes(), content)
            previous = output

    def test_retry_incomplete_checks_stage_facts_in_previously_misclassified_store(
        self,
    ):
        artifact = self.artifact()
        for version in (1, 2):
            source = self.store(f"misclassified-source-{version}.sqlite3")
            source.save_artifact(
                artifact["sha256"], self.result(artifact["sha256"], "PARTIAL")
            )
            source.connection.execute("UPDATE artifacts SET status='COMPLETE'")
            legacy_store_layout(source.connection, version)
            source.connection.commit()
            previous = AnalysisStore(source.path, readonly=True)
            self.addCleanup(previous.close)
            before = source.path.read_bytes()
            for retry_incomplete in (False, True):
                with self.subTest(version=version, retry_incomplete=retry_incomplete):
                    target = self.store(
                        f"misclassified-target-{version}-{retry_incomplete}.sqlite3"
                    )
                    with patch(
                        "scripts.static_analysis.engine.analyze_artifact",
                        wraps=analyze_artifact,
                    ) as parser:
                        analyze_many(
                            [artifact],
                            self.limits,
                            "standard",
                            self.cancel,
                            1,
                            None,
                            lambda event: None,
                            store=target,
                            resume_store=previous,
                            retry_incomplete=retry_incomplete,
                        )
                    self.assertEqual(parser.call_count, int(retry_incomplete))
                    status = target.connection.execute(
                        "SELECT status FROM artifacts"
                    ).fetchone()[0]
                    self.assertEqual(
                        status, "COMPLETE" if retry_incomplete else "PARTIAL"
                    )
                    self.assertEqual(source.path.read_bytes(), before)

    def test_progress_distinguishes_failed_results_from_successes(self):
        artifact = {"sha256": "synthetic"}
        store = self.store("analysis.sqlite3")
        events = []
        with patch(
            "scripts.static_analysis.engine.analyze_artifact",
            return_value=self.result("synthetic", "FAILED"),
        ):
            analyze_many(
                [artifact],
                self.limits,
                "standard",
                self.cancel,
                1,
                None,
                events.append,
                store=store,
            )
        self.assertEqual(events[0]["done"], 1)
        self.assertEqual(events[0]["complete"], 0)
        self.assertEqual(events[0]["failed"], 1)
        self.assertEqual(events[0]["status"], "FAILED")

    def test_worker_results_are_released_after_checkpointing(self):
        class TrackedResult(dict):
            pass

        references = []

        def parse(artifact, *args):
            result = TrackedResult(self.result(artifact["sha256"]))
            result["endpoints"] = [
                {"id": str(index), "value": "https://example.org/" + str(index)}
                for index in range(100)
            ]
            references.append(weakref.ref(result))
            return result

        artifacts = [{"sha256": f"{index:064x}"} for index in range(40)]
        store = self.store("analysis.sqlite3")
        with patch(
            "scripts.static_analysis.engine.analyze_artifact", side_effect=parse
        ):
            results = analyze_many(
                artifacts,
                self.limits,
                "standard",
                self.cancel,
                2,
                None,
                lambda event: None,
                store=store,
            )
        self.assertIsInstance(results, ArtifactResults)
        self.assertEqual(sum(reference() is not None for reference in references), 0)
        self.assertEqual(len(results), len(artifacts))

    def test_memory_guard_stops_dispatch_and_preserves_checkpoints(self):
        artifacts = [{"sha256": f"{index:064x}"} for index in range(3)]
        store = self.store("analysis.sqlite3")
        limited = self.result(artifacts[0]["sha256"], "PARTIAL", resource_limited=True)
        with patch(
            "scripts.static_analysis.engine.analyze_artifact", return_value=limited
        ) as parser:
            results = analyze_many(
                artifacts,
                self.limits,
                "standard",
                self.cancel,
                1,
                None,
                lambda event: None,
                store=store,
            )
        self.assertEqual(parser.call_count, 1)
        self.assertTrue(self.cancel.is_set())
        self.assertEqual(len(results), 3)
        self.assertEqual(
            next(iter(results[artifacts[1]["sha256"]]["stages"]))["status"], "CANCELLED"
        )

    def test_memory_budget_does_not_invalidate_compatible_caches(self):
        self.assertEqual(
            cache_key("artifact", self.limits, "standard"),
            cache_key("artifact", replace(self.limits, memory_bytes=1), "standard"),
        )
        with (
            patch("scripts.static_analysis.common.resident_bytes", return_value=100),
            self.assertRaises(MemoryBudgetExceeded),
        ):
            Budget(replace(self.limits, memory_bytes=99)).check()

    def test_preflight_reduces_concurrency_with_memory_headroom(self):
        with (
            patch(
                "scripts.static_analysis.tasks.available_memory",
                return_value=1000 * MIB,
            ),
            patch(
                "scripts.static_analysis.tasks.resident_bytes", return_value=100 * MIB
            ),
        ):
            plan = resource_plan([], self.root, self.limits, 8, None)
        self.assertEqual(plan["memory_budget_bytes"], 700 * MIB)
        self.assertEqual(plan["jobs"], 1)
        self.assertEqual(plan["requested_jobs"], 8)

    def test_memory_preflight_uses_process_cgroup_and_ancestor_limits(self):
        files = {
            "/proc/meminfo": "MemAvailable: 10485760 kB\n",
            "/proc/self/cgroup": "0::/parent/worker\n",
            "/sys/fs/cgroup/memory.max": "max",
            "/sys/fs/cgroup/parent/worker/memory.max": str(2048 * MIB),
            "/sys/fs/cgroup/parent/worker/memory.current": str(512 * MIB),
            "/sys/fs/cgroup/parent/memory.max": str(1024 * MIB),
            "/sys/fs/cgroup/parent/memory.current": str(256 * MIB),
        }

        def read(path, *args, **kwargs):
            if str(path) not in files:
                raise FileNotFoundError(str(path))
            return files[str(path)]

        with patch.object(Path, "read_text", autospec=True, side_effect=read):
            self.assertEqual(available_memory(), 768 * MIB)

    def test_atomic_stream_failure_preserves_previous_file(self):
        from collections.abc import Sequence

        class InterruptedSequence(Sequence):
            def __len__(self):
                return 2

            def __getitem__(self, index):
                if index == 0:
                    return {"first": True}
                raise ValueError("Simulated export interruption")

        path = self.root / "analysis.json"
        path.write_text("original", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "interruption"):
            atomic_json(path, {"apps": InterruptedSequence()})
        self.assertEqual(path.read_text(), "original")
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_streamed_cache_checksums_match_existing_cache_contract(self):
        value = {"text": "\U0001f600", "record": [{"id": "evidence", "index": 3}]}
        expected = hashlib.sha256(
            json.dumps(value, sort_keys=True, ensure_ascii=True).encode()
        ).hexdigest()
        self.assertEqual(json_checksum(value), expected)

    def test_collect_only_and_offline_snapshot_reuse_artifacts(self):
        apk = make_apk(self.root / "input.apk", entries={"classes.dex": make_dex()})
        collected = self.root / "collected"
        completed = self.cli("--apk", apk, "--collect-only", "--output", collected)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse((collected / "analysis.sqlite3").exists())
        self.assertFalse((collected / "analysis.json").exists())
        snapshot = load_snapshot(collected / "snapshot.json")
        self.assertTrue(snapshot["collection_complete"])
        output = self.root / "offline"
        completed = self.cli(
            "--snapshot",
            collected / "snapshot.json",
            "--adb",
            "/missing/adb",
            "--output",
            output,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse((output / "artifacts").exists())
        report = load_report(output / "analysis.sqlite3")
        self.addCleanup(close_report, report)
        self.assertEqual(
            report["artifacts"][0]["path"], snapshot["artifacts"][0]["path"]
        )
        self.assertEqual(report["totals"]["apps"], 1)
        queried = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "query_results.py"),
                str(output / "analysis.sqlite3"),
                "--section",
                "endpoints",
                "--limit",
                "1",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(queried.returncode, 0, queried.stderr)
        self.assertEqual(len(json.loads(queried.stdout)["items"]), 1)
        exported = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "export_report.py"),
                str(output / "analysis.sqlite3"),
                "--output",
                str(self.root / "reexport"),
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertTrue((self.root / "reexport" / "summary.json").is_file())

    @unittest.skipUnless(
        Path("/proc/self/statm").is_file(), "Linux RSS sampling is unavailable"
    )
    def test_cli_memory_stop_can_resume_with_a_larger_budget(self):
        apk = make_apk(self.root / "input.apk")
        stopped = self.root / "stopped"
        completed = self.cli("--apk", apk, "--memory-mib", "1", "--output", stopped)
        self.assertEqual(completed.returncode, 130, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["stop_reason"], "memory_budget")
        self.assertEqual(
            json.loads((stopped / "progress.json").read_text())["event"], "interrupted"
        )
        resumed = self.cli(
            "--resume",
            stopped,
            "--memory-mib",
            "512",
            "--output",
            self.root / "resumed",
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertTrue((self.root / "resumed" / "analysis.json").is_file())

    @unittest.skipUnless(
        Path("/proc/self/statm").is_file(), "Linux RSS sampling is unavailable"
    )
    def test_complete_checkpoint_resume_obeys_lower_memory_budget(self):
        apk = make_apk(self.root / "input.apk")
        original = self.root / "original"
        completed = self.cli("--apk", apk, "--no-cache", "--output", original)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        before = (original / "analysis.sqlite3").read_bytes()
        output = self.root / "low-memory-resume"
        completed = self.cli(
            "--resume",
            original,
            "--memory-mib",
            "1",
            "--no-cache",
            "--output",
            output,
        )
        self.assertEqual(completed.returncode, 130, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["stop_reason"], "memory_budget")
        progress = json.loads((output / "progress.json").read_text())
        self.assertEqual(progress["event"], "interrupted")
        self.assertEqual(progress["stop_reason"], "memory_budget")
        self.assertFalse((output / "analysis.json").exists())
        self.assertEqual((original / "analysis.sqlite3").read_bytes(), before)
        completed = self.cli(
            "--resume",
            original,
            "--memory-mib",
            "512",
            "--no-cache",
            "--output",
            self.root / "adequate-memory-resume",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        events = [json.loads(line) for line in completed.stderr.splitlines()]
        self.assertTrue(
            next(
                event
                for event in events
                if event["event"] == "analysis.artifact_completed"
            )["resumed"]
        )

    def test_persistence_failure_cancels_other_workers_before_waiting(self):
        artifacts = [
            {"sha256": str(index) * 64, "size": 1, "path": "synthetic.apk"}
            for index in range(3)
        ]
        for failure in ("checkpoint", "progress", "import"):
            with self.subTest(failure=failure):
                cancel = threading.Event()
                started = threading.Event()
                failed = threading.Event()
                observed = []
                dispatched = []
                store = self.store(f"failure-{failure}.sqlite3")
                store.save_artifact("preserved", self.result("preserved"))
                original_save = store.save_artifact
                resume = (
                    self.store("resume-failure.sqlite3")
                    if failure == "import"
                    else None
                )
                if resume:
                    resume.save_artifact(
                        artifacts[1]["sha256"], self.result(artifacts[1]["sha256"])
                    )

                def worker(
                    artifact,
                    limits,
                    mode,
                    current_cancel,
                    cache,
                    *,
                    started=started,
                    failed=failed,
                    observed=observed,
                    dispatched=dispatched,
                    failure=failure,
                ):
                    identity = artifact["sha256"]
                    dispatched.append(identity)
                    if failure != "import" and identity == artifacts[0]["sha256"]:
                        if not started.wait(2):
                            raise RuntimeError("Second worker did not start")
                    else:
                        started.set()
                        if not failed.wait(2):
                            raise RuntimeError("Persistence did not fail")
                        observed.append(current_cancel.wait(1))
                        Budget(limits, current_cancel).check()
                    return self.result(identity)

                def save(
                    identity,
                    result,
                    *,
                    failure=failure,
                    failed=failed,
                    original_save=original_save,
                ):
                    if failure == "checkpoint":
                        failed.set()
                        raise sqlite3.OperationalError("database or disk is full")
                    return original_save(identity, result)

                def progress(event, failed=failed):
                    failed.set()
                    raise OSError("Progress persistence failed")

                def import_checkpoint(source, identity, started=started, failed=failed):
                    if not started.wait(2):
                        raise RuntimeError("Worker did not start")
                    failed.set()
                    raise sqlite3.OperationalError("database or disk is full")

                with (
                    patch(
                        "scripts.static_analysis.engine.analyze_artifact",
                        side_effect=worker,
                    ),
                    patch.object(store, "save_artifact", side_effect=save),
                    patch.object(
                        store, "import_artifact", side_effect=import_checkpoint
                    ),
                    self.assertRaisesRegex(
                        OSError if failure == "progress" else sqlite3.OperationalError,
                        "Progress persistence" if failure == "progress" else "full",
                    ),
                ):
                    analyze_many(
                        artifacts,
                        self.limits,
                        "standard",
                        cancel,
                        2,
                        None,
                        progress,
                        store=store,
                        resume_store=resume,
                    )
                self.assertEqual(observed, [True])
                self.assertTrue(cancel.is_set())
                self.assertNotIn(artifacts[2]["sha256"], dispatched)
                self.assertTrue(
                    store.reusable(
                        "preserved",
                        cache_key("preserved", self.limits, "standard"),
                        False,
                    )
                )
                self.assertEqual(
                    artifacts[0]["sha256"] in ArtifactResults(store),
                    failure == "progress",
                )

    def test_memory_stop_during_checkpoint_import_rolls_back_only_current_artifact(
        self,
    ):
        source = self.store("import-source.sqlite3")
        source.save_artifact(
            "imported",
            self.result(
                "imported", endpoints=[{"id": str(index)} for index in range(4)]
            ),
        )
        before = source.path.read_bytes()
        target = self.store("import-target.sqlite3")
        target.cancel = self.cancel
        target.budget = TaskBudget(replace(self.limits, memory_bytes=MIB), self.cancel)
        target.save_artifact("preserved", self.result("preserved"))
        with (
            patch(
                "scripts.static_analysis.common.resident_bytes",
                side_effect=[0, 0, 2 * MIB],
            ),
            self.assertRaises(MemoryBudgetExceeded),
        ):
            target.import_artifact(source, "imported")
        self.assertTrue(self.cancel.is_set())
        self.assertTrue(target.budget.memory_exceeded)
        self.assertNotIn("imported", ArtifactResults(target))
        self.assertEqual(list(target.records("artifact", "imported", "endpoints")), [])
        self.assertTrue(
            target.reusable(
                "preserved", cache_key("preserved", self.limits, "standard"), False
            )
        )
        self.assertEqual(source.path.read_bytes(), before)
        target.cancel = threading.Event()
        target.budget = TaskBudget(
            replace(self.limits, memory_bytes=MIB), target.cancel
        )
        with patch("scripts.static_analysis.common.resident_bytes", return_value=0):
            target.import_artifact(source, "imported")
        self.assertTrue(
            target.reusable(
                "imported", cache_key("imported", self.limits, "standard"), False
            )
        )
        self.assertFalse(target.artifact("imported").get("resource_limited", False))
        self.assertEqual(len(target.artifact("imported")["endpoints"]), 4)

    def test_restored_collection_cancellation_is_a_historical_gap(self):
        artifact = self.artifact()
        artifact["package_hint"] = "com.example.app"
        historical = stage("collection", "CANCELLED", "com.example.pending", "Stopped")
        device = {
            "serial": "synthetic-serial",
            "user": 10,
            "stages": [historical],
            "installed_count": 2,
            "selected_packages": ["com.example.app", "com.example.pending"],
            "excluded_packages": [],
            "packages": {
                "com.example.app": {
                    "version_code": "1",
                    "stages": [historical],
                    "permissions": {},
                    "appops": {},
                    "special_access": {},
                }
            },
        }
        original = self.root / "collection"
        save_snapshot(
            original / "snapshot.json",
            DEFAULT_CONFIGURATION,
            [artifact],
            device,
            [historical],
            False,
            "device",
        )
        before = (original / "snapshot.json").read_bytes()
        for entrypoint in ("--snapshot", "--resume"):
            for collect_only in (False, True):
                with self.subTest(entrypoint=entrypoint, collect_only=collect_only):
                    output = self.root / f"{entrypoint[2:]}-{collect_only}"
                    completed = self.cli(
                        entrypoint,
                        original / "snapshot.json"
                        if entrypoint == "--snapshot"
                        else original,
                        *(["--collect-only"] if collect_only else []),
                        "--no-cache",
                        "--output",
                        output,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(json.loads(completed.stdout)["status"], "PARTIAL")
                    restored = load_snapshot(output / "snapshot.json")
                    for records in (
                        restored["stages"],
                        restored["device"]["stages"],
                        restored["device"]["packages"]["com.example.app"]["stages"],
                    ):
                        self.assertEqual(records[0]["status"], "PARTIAL")
                        self.assertEqual(records[0]["original_status"], "CANCELLED")
                    if not collect_only:
                        report = load_report(output / "analysis.json")
                        self.assertIsNone(report["run"]["stop_reason"])
                        self.assertTrue(
                            all(app["status"] == "PARTIAL" for app in report["apps"])
                        )
                        self.assertNotIn(
                            "CANCELLED", summary(report)["coverage_counts"]
                        )
                        progress = json.loads((output / "progress.json").read_text())
                        self.assertEqual(progress["event"], "completed")
                        self.assertEqual(progress["status"], "PARTIAL")
        completed = self.cli(
            "--resume",
            self.root / "resume-False",
            "--no-cache",
            "--output",
            self.root / "resumed-again",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        restored = load_snapshot(self.root / "resumed-again" / "snapshot.json")
        self.assertEqual(restored["stages"][0]["original_status"], "CANCELLED")
        self.assertEqual(restored["stages"][0]["status"], "PARTIAL")
        program = """
import sys
sys.path.insert(0, sys.argv[1])
import analyze
original = analyze.verify_artifacts
def verify(artifacts, cancel):
    cancel.set()
    return original(artifacts, cancel)
analyze.verify_artifacts = verify
args = analyze.build_parser().parse_args(["scan", "--snapshot", sys.argv[2], "--output", sys.argv[3], "--quiet"])
raise SystemExit(analyze.scan(args))
"""
        output = self.root / "current-cancellation"
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                program,
                str(ROOT / "scripts"),
                str(original / "snapshot.json"),
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 130, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["stop_reason"], "cancelled")
        self.assertEqual(
            json.loads((output / "progress.json").read_text())["event"], "interrupted"
        )
        self.assertEqual((original / "snapshot.json").read_bytes(), before)

    def test_cli_persistence_failures_keep_original_failure_classification(self):
        apk = make_apk(self.root / "input.apk")
        program = """
import sqlite3
import sys
sys.path.insert(0, sys.argv[1])
import analyze
if sys.argv[4] == "checkpoint":
    def save(*args, **options):
        raise sqlite3.OperationalError("database or disk is full")
    analyze.AnalysisStore.save_artifact = save
else:
    original = analyze.atomic_json
    def write(path, value, *args, **options):
        if value.get("event") == "artifact_complete":
            raise OSError("Progress persistence failed")
        return original(path, value, *args, **options)
    analyze.atomic_json = write
sys.argv = ["analyze.py", "scan", "--apk", sys.argv[2], "--output", sys.argv[3], "--no-cache", "--quiet"]
raise SystemExit(analyze.main())
"""
        for phase in ("checkpoint", "progress"):
            with self.subTest(phase=phase):
                output = self.root / f"cli-failure-{phase}"
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
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(completed.stdout, "")
                diagnostic = json.loads(completed.stderr.splitlines()[-1])
                self.assertEqual(diagnostic["event"], "analysis.failed")
                self.assertEqual(diagnostic["status"], "FAILED")
                self.assertIn(
                    "full" if phase == "checkpoint" else "Progress persistence",
                    diagnostic["error"],
                )
                store = AnalysisStore(output / "analysis.sqlite3", readonly=True)
                try:
                    self.assertEqual(
                        len(ArtifactResults(store)), 1 if phase == "progress" else 0
                    )
                finally:
                    store.close()

    def test_aggregation_cancellation_preserves_artifact_checkpoints(self):
        store = self.store("analysis.sqlite3")
        store.cancel = self.cancel
        store.save_artifact("artifact", self.result("artifact"))

        def records():
            yield {"id": "first", "evidence": [], "evidence_level": "E1"}
            self.cancel.set()
            yield {"id": "second", "evidence": [], "evidence_level": "E1"}

        from scripts.static_analysis.common import Cancelled

        with self.assertRaises(Cancelled):
            store.merge("application", "endpoints", records(), self.limits)
        store.connection.rollback()
        self.assertTrue(
            store.reusable(
                "artifact", cache_key("artifact", self.limits, "standard"), False
            )
        )
        self.assertFalse(list(store.records("app", "application", "endpoints")))

    def test_cli_resume_inherits_configuration_and_preserves_original_task(self):
        apk = make_apk(self.root / "input.apk")
        first = self.root / "first"
        completed = self.cli(
            "--apk",
            apk,
            "--mode",
            "quick",
            "--max-results",
            "100",
            "--no-cache",
            "--output",
            first,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in first.iterdir()
            if path.is_file()
        }
        second = self.root / "second"
        completed = self.cli("--resume", first, "--no-cache", "--output", second)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        events = [json.loads(line) for line in completed.stderr.splitlines()]
        self.assertTrue(
            next(
                event
                for event in events
                if event["event"] == "analysis.artifact_completed"
            )["resumed"]
        )
        self.assertEqual(
            load_snapshot(second / "snapshot.json")["configuration"]["max_results"], 100
        )
        self.assertEqual(
            json.loads((second / "analysis.json").read_text())["run"]["mode"], "quick"
        )
        self.assertEqual(
            before,
            {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in first.iterdir()
                if path.is_file()
            },
        )

    def test_changed_saved_artifacts_fail_before_checkpoint_reuse(self):
        apk = make_apk(self.root / "input.apk")
        first = self.root / "first"
        self.assertEqual(self.cli("--apk", apk, "--output", first).returncode, 0)
        artifact = load_snapshot(first / "snapshot.json")["artifacts"][0]
        with Path(artifact["path"]).open("ab") as handle:
            handle.write(b"changed")
        second = self.root / "second"
        completed = self.cli("--resume", first, "--output", second)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("identity changed", completed.stderr)
        self.assertFalse((second / "analysis.sqlite3").exists())

    def test_offline_device_snapshot_preserves_user_grants_appops_and_missing_targets(
        self,
    ):
        artifact = self.artifact()
        artifact["package_hint"] = "com.example.app"
        device = {
            "serial": "synthetic-serial",
            "user": 10,
            "stages": [],
            "installed_count": 2,
            "selected_packages": ["com.example.app", "com.example.pending"],
            "excluded_packages": [],
            "packages": {
                "com.example.app": {
                    "version_code": "1",
                    "stages": [],
                    "permissions": {
                        "android.permission.CAMERA": {
                            "granted": True,
                            "source": "runtime_user",
                        }
                    },
                    "appops": {"CAMERA": "allow"},
                    "special_access": {"default_input_method": False},
                }
            },
        }
        snapshot_path = self.root / "snapshot.json"
        save_snapshot(
            snapshot_path,
            DEFAULT_CONFIGURATION,
            [artifact],
            device,
            [],
            False,
            "device",
        )
        output = self.root / "offline"
        completed = self.cli("--snapshot", snapshot_path, "--output", output)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = load_report(output / "analysis.json")
        app = next(app for app in report["apps"] if app["package"] == "com.example.app")
        self.assertEqual(app["user"], 10)
        self.assertTrue(app["permissions"][0]["granted"])
        self.assertEqual(app["installation"]["appops"]["CAMERA"], "allow")
        pending = next(
            app for app in report["apps"] if app["package"] == "com.example.pending"
        )
        self.assertFalse(pending["artifacts"])
        self.assertEqual(pending["status"], "PARTIAL")
        self.assertEqual(report["run"]["input_kind"], "device")

    def test_device_checkpoint_preserves_completed_pull_before_later_failure(self):
        fixture = make_apk(self.root / "input.apk")
        snapshots = []

        def shell(arguments):
            if arguments[:3] == ["pm", "list", "packages"]:
                output = "package:/data/app/base.apk=com.example.app uid:10123\n"
            elif arguments[:2] == ["dumpsys", "package"]:
                output = "  Package [com.example.app] (a):\n    appId=10123\n    versionCode=1\n"
            elif arguments[:2] == ["pm", "path"]:
                output = "package:/data/app/base.apk\npackage:/data/app/split.apk\n"
            elif arguments[:3] == ["cmd", "appops", "get"]:
                output = "CAMERA: allow\n"
            else:
                output = "null\n"
            return {"status": "COMPLETE", "reason": None, "stdout": output}

        def pull(arguments, **kwargs):
            if arguments[-2].endswith("split.apk"):
                raise OSError("Simulated disconnect")
            Path(arguments[-1]).write_bytes(fixture.read_bytes())
            return {"status": "COMPLETE", "reason": None}

        def checkpoint(snapshot, complete):
            snapshots.append(
                json.loads(json.dumps({"snapshot": snapshot, "complete": complete}))
            )

        collector = DeviceCollector(
            "adb",
            "synthetic-serial",
            10,
            self.root / "run" / "device",
            self.limits,
            self.cancel,
            checkpoint=checkpoint,
        )
        with (
            patch.object(collector, "shell", side_effect=shell),
            patch("scripts.static_analysis.device.run_command", side_effect=pull),
            self.assertRaisesRegex(OSError, "disconnect"),
        ):
            collector.collect([])
        saved = snapshots[-1]
        self.assertFalse(saved["complete"])
        self.assertEqual(len(saved["snapshot"]["artifacts"]), 1)
        self.assertEqual(
            saved["snapshot"]["packages"]["com.example.app"]["appops"]["CAMERA"],
            "allow",
        )
        verify_artifacts(saved["snapshot"]["artifacts"], self.cancel)

    def test_hot_journal_recovery_preserves_source_and_committed_checkpoints(self):
        path = self.root / "interrupted.sqlite3"
        source = self.store(path.name)
        source.save_artifact("committed", self.result("committed"))
        source.close()
        code = (
            "import os, sqlite3, sys; connection=sqlite3.connect(sys.argv[1]); "
            "connection.execute('PRAGMA cache_size=1'); connection.execute('BEGIN IMMEDIATE'); "
            "connection.execute(\"INSERT INTO metadata VALUES ('interrupted',?)\", ('x'*50000,)); os._exit(9)"
        )
        interrupted = subprocess.run(
            [sys.executable, "-c", code, str(path)], check=False
        )
        self.assertEqual(interrupted.returncode, 9)
        journal = Path(str(path) + "-journal")
        before = [
            hashlib.sha256(item.read_bytes()).hexdigest() for item in (path, journal)
        ]
        with checkpoint_source(path, self.root) as recovered:
            self.assertEqual(recovered.artifact("committed")["sha256"], "committed")
            self.assertIsNone(recovered.metadata("interrupted"))
        self.assertEqual(
            before,
            [hashlib.sha256(item.read_bytes()).hexdigest() for item in (path, journal)],
        )
        self.assertFalse(list(self.root.glob(".recovery-*")))

    def test_checkpoint_transaction_rolls_back_partial_replacement(self):
        store = self.store("analysis.sqlite3")
        store.save_artifact("artifact", self.result("artifact"))
        replacement = self.result(
            "artifact", endpoints=[{"id": "bad", "value": float("nan")}]
        )
        with self.assertRaises(ValueError):
            store.save_artifact("artifact", replacement)
        self.assertEqual(list(store.artifact("artifact")["endpoints"]), [])
        self.assertTrue(
            store.reusable(
                "artifact", cache_key("artifact", self.limits, "standard"), False
            )
        )

    def test_changed_decompiler_does_not_reuse_stale_supplemental_results(self):
        store = self.store("analysis.sqlite3")
        result = self.result(
            "artifact", source_view_complete=True, source_view_tool="old-jadx"
        )
        store.save_artifact("artifact", result)
        key = cache_key("artifact", self.limits, "standard")
        self.assertTrue(store.reusable("artifact", key, False, "old-jadx"))
        self.assertFalse(store.reusable("artifact", key, False, "new-jadx"))

    def test_checkpoint_database_without_report_requires_resume(self):
        store = self.store("analysis.sqlite3")
        store.save_artifact("artifact", self.result("artifact"))
        with self.assertRaisesRegex(AnalysisError, "resume"):
            load_report(store.path)

    def test_invalid_database_fails_without_creating_input(self):
        missing = self.root / "missing.sqlite3"
        with self.assertRaises(AnalysisError):
            load_report(missing)
        self.assertFalse(missing.exists())
        malformed = self.root / "malformed.sqlite3"
        malformed.write_text("not a database", encoding="utf-8")
        with self.assertRaises(AnalysisError):
            load_report(malformed)


if __name__ == "__main__":
    unittest.main()
