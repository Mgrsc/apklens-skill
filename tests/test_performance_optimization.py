import copy
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from support import legacy_store_layout

from scripts.static_analysis import dataflow, engine, rules
from scripts.static_analysis.common import (
    AnalysisError,
    Cancelled,
    DiskBudgetExceeded,
    JsonRecordMapping,
    JsonRecords,
    Limits,
    TaskBudget,
    atomic_json,
    json_chunks,
    record_chunks,
    stage,
)
from scripts.static_analysis.metrics import PerformanceMetrics
from scripts.static_analysis.storage import (
    INSERT_STATEMENT_ROWS,
    RECORD_BATCH_ROWS,
    AnalysisStore,
    ArtifactResults,
)
from scripts.static_analysis.tasks import resource_plan, save_snapshot, snapshot_payload


class PerformanceOptimizationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()

    def store(self, name):
        result = AnalysisStore(self.root / name)
        self.addCleanup(result.close)
        return result

    def artifact(self, **values):
        return {
            "sha256": "source",
            "manifest": None,
            "endpoints": [],
            "signals": [],
            "sdks": [],
            "stages": [stage("analysis")],
            "methods": [],
            "fields": [],
            **values,
        }

    def test_snapshot_fast_encoding_matches_original_and_does_not_mutate_input(self):
        device = {
            "packages": {"example": {"text": "\U0001f600", "stages": [stage("test")]}},
            "stages": [stage("inventory")],
            "artifacts": [],
        }
        before = copy.deepcopy(device)
        expected = (
            "".join(json_chunks(snapshot_payload({}, [], device, [], True, "device")))
            + "\n"
        )
        output = self.root / "snapshot.json"
        save_snapshot(output, {}, [], device, [], True, "device")
        self.assertEqual(output.read_text(), expected)
        self.assertEqual(device, before)

    def test_bounded_records_fallback_preserves_nan_and_cancellation(self):
        large = {"text": "x" * 300000, "values": list(range(5000))}
        values = JsonRecordMapping({"first": large, "second": {"text": "ok"}})
        self.assertEqual(
            "".join(json_chunks(values)), "".join(json_chunks(values.values))
        )
        output = self.root / "records.json"
        output.write_text("preserved")
        with self.assertRaises(ValueError):
            atomic_json(output, JsonRecords([{"value": float("nan")}], bounded=True))
        self.assertEqual(output.read_text(), "preserved")
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(Cancelled):
            atomic_json(output, values, cancel)

    def test_oversized_records_encode_bounded_nested_records(self):
        records = [{"index": index, "value": "ok"} for index in range(12)]
        for value in (records, {"records": records}):
            with (
                self.subTest(kind=type(value).__name__),
                patch("scripts.static_analysis.common.JSON_RECORD_ITEMS", 16),
                patch("scripts.static_analysis.common.JSON_RECORD_CHARACTERS", 256),
            ):
                chunks = list(record_chunks(value))
                self.assertEqual(
                    "".join(chunks),
                    json.dumps(value, ensure_ascii=False, separators=(",", ":")),
                )
                self.assertIn('{"index":0,"value":"ok"}', chunks)
                self.assertLessEqual(max(map(len, chunks)), 256)

    def test_signal_cache_retains_provenance_and_bypasses_long_text(self):
        rules.cached_signal_decisions.cache_clear()
        text = "ClipboardManager getInstalledApplications"
        first = rules.signal_matches(text, {"entry": "first"})
        second = rules.signal_matches(text, {"entry": "second"})
        self.assertEqual(
            [item["type"] for item in first], [item["type"] for item in second]
        )
        self.assertNotEqual(
            first[0]["evidence"][0]["id"], second[0]["evidence"][0]["id"]
        )
        first[0]["evidence"].clear()
        self.assertTrue(rules.signal_matches(text, {"entry": "first"})[0]["evidence"])
        before = rules.cached_signal_decisions.cache_info()
        rules.signal_matches(text * rules.SIGNAL_CACHE_TEXT_LENGTH, {})
        after = rules.cached_signal_decisions.cache_info()
        self.assertEqual(before, after)

    def test_immutable_leaves_share_but_mutable_state_and_invalid_leaves_do_not(self):
        node = dataflow.Node("artifact", "classes.dex", "method", 0, "test", "target")
        value = dataflow.Value(
            sources=(dataflow.Source("identifier", (node,)),), constants=("text",)
        )
        state = {"heap": {"object": {"fields": {"field": value}}}, "conditions": []}
        copied = copy.deepcopy(state)
        self.assertIs(copied["heap"]["object"]["fields"]["field"], value)
        copied["heap"]["object"]["fields"]["other"] = value
        copied["conditions"].append("branch")
        self.assertNotIn("other", state["heap"]["object"]["fields"])
        self.assertEqual(state["conditions"], [])
        mutable = dataflow.Value(constants=(["mutable"],))
        copied_mutable = copy.deepcopy(mutable)
        copied_mutable.constants[0].append("changed")
        self.assertEqual(mutable.constants[0], ["mutable"])

    def test_discarded_gap_keeps_counts_without_building_node(self):
        analyzer = dataflow.Analyzer([], self.limits)
        node = dataflow.Node("artifact", "classes.dex", "method", 0, "test", "target")
        for index in range(dataflow.MAX_GAPS):
            analyzer.gap(f"Unsupported: {index}", node)
        with patch.object(
            dataflow.Node,
            "record",
            side_effect=AssertionError("Discarded node was materialized"),
        ):
            analyzer.gap("Unsupported: additional", node)
            analyzer.gap("Another: additional", node)
        self.assertEqual(analyzer.gap_counts["Unsupported"], dataflow.MAX_GAPS + 1)
        self.assertEqual(analyzer.gap_counts["Another"], 1)
        self.assertIn("truncated", analyzer.gaps)

    def test_raw_import_renumbers_sparse_ordinals_and_preserves_status(self):
        source = self.store("source.sqlite3")
        target = self.store("target.sqlite3")
        source.save_artifact(
            "source",
            self.artifact(
                endpoints=[{"id": "one"}, {"id": "two"}],
                stages=[stage("analysis", "PARTIAL")],
            ),
        )
        legacy_store_layout(source.connection, 3)
        source.version = 3
        source.connection.execute(
            "UPDATE records SET ordinal=ordinal*3+5 WHERE section='endpoints'"
        )
        source.connection.commit()
        target.import_artifact(source, "source")
        self.assertEqual(
            list(target.artifact("source")["endpoints"]), [{"id": "one"}, {"id": "two"}]
        )
        self.assertEqual(
            target.connection.execute(
                "SELECT ordinal FROM records WHERE section='endpoints' ORDER BY ordinal"
            ).fetchall(),
            [(0,), (1,)],
        )
        self.assertEqual(
            target.connection.execute("SELECT status FROM artifacts").fetchone()[0],
            "PARTIAL",
        )

    def test_raw_import_rejects_bad_json_and_rolls_back_replacement(self):
        source = self.store("source.sqlite3")
        target = self.store("target.sqlite3")
        original = self.artifact(endpoints=[{"id": "preserved"}])
        source.save_artifact("source", original)
        target.save_artifact("source", original)
        source.connection.execute(
            "UPDATE facts SET payload='{' WHERE fact_id=(SELECT r.fact_id FROM record_refs r JOIN sections s ON s.code=r.section_code WHERE s.name='endpoints' LIMIT 1)"
        )
        source.connection.commit()
        with self.assertRaises((AnalysisError, sqlite3.DatabaseError)):
            target.import_artifact(source, "source")
        self.assertEqual(
            list(target.artifact("source")["endpoints"]), original["endpoints"]
        )

    def test_initial_seed_falls_back_for_duplicate_business_ids(self):
        store = self.store("source.sqlite3")
        first = {"id": "shared", "evidence_level": "E1", "evidence": [{"id": "one"}]}
        second = {"id": "shared", "evidence_level": "E2", "evidence": [{"id": "two"}]}
        store.save_artifact("source", self.artifact(endpoints=[first, second]))
        self.assertFalse(
            store.merge(
                "app", "endpoints", store.artifact("source")["endpoints"], self.limits
            )
        )
        merged = list(store.records("app", "app", "endpoints"))
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["evidence_level"], "E2")
        self.assertEqual(merged[0]["evidence"], [{"id": "one"}, {"id": "two"}])

    def test_seed_unique_records_skips_per_record_target_selects(self):
        store = self.store("source.sqlite3")
        store.save_artifact(
            "source",
            self.artifact(endpoints=[{"id": str(index)} for index in range(20)]),
        )
        statements = []
        store.connection.set_trace_callback(statements.append)
        store.merge(
            "app", "endpoints", store.artifact("source")["endpoints"], self.limits
        )
        self.assertFalse(
            any(
                "SELECT payload FROM records WHERE scope='app'" in statement
                for statement in statements
            )
        )
        self.assertEqual(len(store.records("app", "app", "endpoints")), 20)

    def test_missing_json_functions_uses_safe_import_path(self):
        source = self.store("source.sqlite3")
        target = self.store("target.sqlite3")
        source.save_artifact("source", self.artifact(endpoints=[{"id": "one"}]))
        source.json_functions = False
        target.import_artifact(source, "source")
        self.assertEqual(list(target.artifact("source")["endpoints"]), [{"id": "one"}])

    def fact_id(self, store, scope, owner, section):
        return store.connection.execute(
            "SELECT r.fact_id FROM record_refs r JOIN owners o ON o.owner_id=r.owner_id JOIN sections s ON s.code=r.section_code WHERE o.scope=? AND o.identity=? AND s.name=? ORDER BY r.ordinal LIMIT 1",
            (scope, owner, section),
        ).fetchone()[0]

    def test_v4_shared_payloads_use_copy_on_write_for_each_owner(self):
        store = self.store("shared.sqlite3")
        original = {"id": "one", "tags": [], "evidence": [], "evidence_level": "E1"}
        store.save_artifact("source", self.artifact(endpoints=[original]))
        for owner in ("first", "second"):
            store.merge(
                owner, "endpoints", store.artifact("source")["endpoints"], self.limits
            )
        original_id = self.fact_id(store, "artifact", "source", "endpoints")
        self.assertEqual(self.fact_id(store, "app", "first", "endpoints"), original_id)
        self.assertEqual(self.fact_id(store, "app", "second", "endpoints"), original_id)
        store.update_record("first", "endpoints", {**original, "tags": ["changed"]})
        store._cleanup_facts()
        store.connection.commit()
        self.assertNotEqual(
            self.fact_id(store, "app", "first", "endpoints"), original_id
        )
        self.assertEqual(store.artifact("source")["endpoints"][0], original)
        self.assertEqual(store.records("app", "second", "endpoints")[0], original)
        self.assertEqual(
            store.connection.execute("PRAGMA foreign_key_check").fetchall(), []
        )

    def test_v4_split_merge_shares_new_facts_without_rewriting_source(self):
        store = self.store("split.sqlite3")
        for owner, records in (
            ("base", [{"id": "shared", "evidence": [{"id": "base"}]}]),
            (
                "split",
                [
                    {"id": "shared", "evidence": [{"id": "split"}]},
                    {"id": "unique", "evidence": []},
                ],
            ),
        ):
            store.save_artifact(owner, self.artifact(endpoints=records))
            store.merge(
                "app", "endpoints", store.artifact(owner)["endpoints"], self.limits
            )
        records = list(store.records("app", "app", "endpoints"))
        self.assertEqual([item["id"] for item in records], ["shared", "unique"])
        self.assertEqual(records[0]["evidence"], [{"id": "base"}, {"id": "split"}])
        self.assertEqual(
            store.artifact("base")["endpoints"][0]["evidence"], [{"id": "base"}]
        )
        shared = store.connection.execute(
            "SELECT r.fact_id FROM record_refs r JOIN owners o ON o.owner_id=r.owner_id WHERE o.scope='app' AND o.identity='app' AND r.identity='unique'"
        ).fetchone()[0]
        source = store.connection.execute(
            "SELECT r.fact_id FROM record_refs r JOIN owners o ON o.owner_id=r.owner_id JOIN facts f ON f.fact_id=r.fact_id WHERE o.scope='artifact' AND o.identity='split' AND json_extract(f.payload,'$.id')='unique'"
        ).fetchone()[0]
        self.assertEqual(shared, source)

    def test_v4_replacing_artifact_keeps_shared_facts_and_removes_only_orphans(self):
        store = self.store("replace.sqlite3")
        store.save_artifact(
            "source", self.artifact(fields=[{"id": "field", "value": "preserved"}])
        )
        store.merge("app", "fields", store.artifact("source")["fields"], self.limits)
        store.connection.commit()
        store.save_artifact("source", self.artifact(fields=[{"id": "new"}]))
        self.assertEqual(store.records("app", "app", "fields")[0]["value"], "preserved")
        self.assertEqual(
            store.connection.execute(
                "SELECT COUNT(*) FROM facts f WHERE NOT EXISTS (SELECT 1 FROM record_refs r WHERE r.fact_id=f.fact_id)"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            store.connection.execute("PRAGMA foreign_key_check").fetchall(), []
        )

    def test_application_failure_rolls_back_shared_references_and_can_continue(self):
        store = self.store("application-failure.sqlite3")
        store.save_artifact("source", self.artifact(endpoints=[{"id": "one"}]))
        with (
            patch.object(
                engine,
                "analyze_dataflow",
                side_effect=ValueError("Synthetic application failure"),
            ),
            self.assertRaisesRegex(ValueError, "Synthetic application failure"),
        ):
            engine.build_apps(
                [{"sha256": "source", "size": 1}],
                ArtifactResults(store),
                None,
                self.limits,
                "standard",
                store=store,
            )
        self.assertEqual(
            store.connection.execute(
                "SELECT COUNT(*) FROM owners WHERE scope='app'"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            store.connection.execute("SELECT COUNT(*) FROM apps").fetchone()[0], 0
        )
        store.save_artifact("next", self.artifact())
        self.assertEqual(list(store.artifact("source")["endpoints"]), [{"id": "one"}])
        self.assertEqual(store.positions.get(("artifact", "next", "stages")), 1)

    def test_application_failure_preserves_previously_committed_application(self):
        store = self.store("application-checkpoint.sqlite3")
        artifacts = [
            {"sha256": identity, "size": 1, "package_hint": f"example.{identity}"}
            for identity in ("first", "second")
        ]
        for artifact in artifacts:
            store.save_artifact(
                artifact["sha256"],
                self.artifact(
                    sha256=artifact["sha256"],
                    fields=[{"id": artifact["sha256"]}],
                ),
            )
        events = []
        with (
            patch.object(
                engine,
                "analyze_dataflow",
                side_effect=[
                    ([], []),
                    ValueError("Synthetic second application failure"),
                ],
            ),
            self.assertRaisesRegex(ValueError, "Synthetic second application failure"),
        ):
            engine.build_apps(
                artifacts,
                ArtifactResults(store),
                None,
                self.limits,
                "standard",
                store=store,
                progress=events.append,
            )
        self.assertEqual(len(events), 1)
        self.assertEqual(
            store.connection.execute("SELECT identity FROM apps").fetchall(),
            [(events[0]["app_id"],)],
        )
        self.assertEqual(
            store.connection.execute(
                "SELECT identity FROM owners WHERE scope='app'"
            ).fetchall(),
            [(events[0]["app_id"],)],
        )
        self.assertEqual(
            list(store.records("app", events[0]["app_id"], "fields")),
            [{"id": "first"}],
        )
        self.assertEqual(len(ArtifactResults(store)), 2)
        self.assertEqual(store.positions, {})
        self.assertFalse(store.connection.in_transaction)
        self.assertEqual(
            store.connection.execute("PRAGMA foreign_key_check").fetchall(), []
        )

    def test_disk_preflight_and_runtime_reserve_stop_without_deleting_files(self):
        preserved = self.root / "preserved"
        preserved.write_text("preserved")
        with (
            patch(
                "scripts.static_analysis.tasks.shutil.disk_usage",
                return_value=SimpleNamespace(free=1),
            ),
            self.assertRaisesRegex(AnalysisError, "Insufficient disk"),
        ):
            resource_plan([], self.root, self.limits, 2, None)
        cancel = threading.Event()
        budget = TaskBudget(self.limits, cancel, self.root, min_free_bytes=10)
        with (
            patch(
                "scripts.static_analysis.common.shutil.disk_usage",
                return_value=SimpleNamespace(free=1),
            ),
            self.assertRaises(DiskBudgetExceeded),
        ):
            budget.check()
        self.assertTrue(cancel.is_set())
        self.assertTrue(budget.disk_exceeded)
        self.assertEqual(preserved.read_text(), "preserved")

    def test_native_insert_batches_preserve_order_with_legacy_variable_limit(self):
        store = self.store("native-batches.sqlite3")
        if hasattr(store.connection, "setlimit"):
            store.connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
        count = RECORD_BATCH_ROWS * 2 + 3
        records = [{"id": str(index), "value": "text"} for index in range(count)]
        statements = []
        store.connection.set_trace_callback(statements.append)
        store.save_artifact("source", self.artifact(fields=records))
        self.assertEqual(list(store.artifact("source")["fields"]), records)
        inserts = [
            sql
            for sql in statements
            if sql.startswith("INSERT INTO record_refs VALUES")
        ]
        self.assertGreaterEqual(
            len(inserts), (count + INSERT_STATEMENT_ROWS - 1) // INSERT_STATEMENT_ROWS
        )
        self.assertLess(len(inserts), count // 2)
        self.assertEqual(
            store.connection.execute("PRAGMA foreign_key_check").fetchall(), []
        )

    def test_partial_artifact_persistence_checks_disk_between_batches(self):
        store = self.store("partial-disk.sqlite3")
        cancel = threading.Event()
        cancel.set()
        budget = TaskBudget(self.limits, cancel, self.root, min_free_bytes=10)
        budget.memory_exceeded = True
        store.budget = budget
        original = self.artifact(
            endpoints=[{"id": "retained"}],
            stages=[stage("analysis", "PARTIAL")],
            resource_limited=True,
        )
        store.save_artifact("source", original)
        replacement = self.artifact(
            endpoints=[{"id": str(index)} for index in range(RECORD_BATCH_ROWS + 1)]
        )
        budget.next_disk_check = 0
        with (
            patch(
                "scripts.static_analysis.common.time.monotonic",
                side_effect=iter(range(0, 100, 2)),
            ),
            patch(
                "scripts.static_analysis.common.shutil.disk_usage",
                side_effect=[SimpleNamespace(free=100), SimpleNamespace(free=1)],
            ) as disk,
            self.assertRaises(DiskBudgetExceeded),
        ):
            store.save_artifact("source", replacement)
        self.assertEqual(disk.call_count, 2)
        self.assertTrue(budget.disk_exceeded)
        self.assertEqual(
            list(store.artifact("source")["endpoints"]), [{"id": "retained"}]
        )
        self.assertEqual(
            store.connection.execute("SELECT status FROM artifacts").fetchone()[0],
            "PARTIAL",
        )
        self.assertEqual(store.positions, {})

    def test_metrics_capture_interrupted_phase_without_sensitive_inputs(self):
        metrics = PerformanceMetrics(self.root, "run")
        with self.assertRaises(ValueError), metrics.measure("verify"):
            raise ValueError("secret input")
        metrics.close("FAILED")
        value = json.loads((self.root / "performance.json").read_text())
        self.assertEqual(value["status"], "FAILED")
        self.assertEqual(value["phases"]["verify"]["count"], 1)
        self.assertNotIn("secret input", json.dumps(value))
