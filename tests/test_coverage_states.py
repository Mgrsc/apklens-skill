import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from privacy_fixtures import ROOT_METHOD, privacy_dex
from support import make_apk
from test_method_coverage import ordinary, sensitive

from scripts.static_analysis import binary, engine
from scripts.static_analysis.common import Budget, Limits, json_chunks, snapshot_file
from scripts.static_analysis.reports import query
from scripts.static_analysis.storage import (
    AnalysisStore,
    ArtifactResults,
    artifact_status,
)


class CoverageStateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()

    def artifact(self, entries, duplicate=None):
        source = make_apk(self.root / "sample.apk", entries=entries)
        if duplicate is not None:
            with (
                self.assertWarnsRegex(UserWarning, "Duplicate name"),
                zipfile.ZipFile(source, "a") as archive,
            ):
                archive.writestr(*duplicate)
        return snapshot_file(source, self.root / "artifacts", self.limits, self.cancel)

    def stages(self, result):
        return {item["stage"]: item for item in result["stages"]}

    def assert_quick_unknowns(self, result):
        stages = self.stages(result)
        for name, fields in (
            (
                "dex_definition_inventory",
                (
                    "definitions",
                    "unique_identities",
                    "duplicate_identities",
                    "complete",
                ),
            ),
            ("dex_references", ("methods", "scan_complete")),
            ("dex_structure_index", ("methods", "method_definitions")),
        ):
            self.assertEqual(stages[name]["status"], "DEFERRED")
            for field in fields:
                with self.subTest(stage=name, field=field):
                    self.assertIsNone(stages[name]["metrics"][field])

    def test_quick_unexecuted_metrics_remain_unknown(self):
        artifact = self.artifact({"classes.dex": privacy_dex([sensitive()])})
        result = engine.analyze_artifact(artifact, self.limits, "quick", self.cancel)
        self.assert_quick_unknowns(result)
        structure = self.stages(result)["dex_structure_index"]["metrics"]
        self.assertGreater(structure["method_references"], 0)
        self.assertEqual(result["statistics"]["dex_files"], 1)
        self.assertEqual(result["statistics"]["scanned_methods"], 0)

    def test_unknown_metrics_survive_cache_and_store_round_trips(self):
        artifact = self.artifact({"classes.dex": privacy_dex([sensitive()])})
        cache = self.root / "cache"
        first = engine.analyze_artifact(
            artifact, self.limits, "quick", self.cancel, cache
        )
        cached = engine.analyze_artifact(
            artifact, self.limits, "quick", self.cancel, cache
        )
        self.assertTrue(cached["cache"]["hit"])
        self.assert_quick_unknowns(first)
        self.assert_quick_unknowns(cached)
        store = AnalysisStore(self.root / "analysis.sqlite3")
        self.addCleanup(store.close)
        store.save_artifact(artifact["sha256"], cached)
        self.assert_quick_unknowns(store.artifact(artifact["sha256"]))
        imported = AnalysisStore(self.root / "imported.sqlite3")
        self.addCleanup(imported.close)
        imported.import_artifact(store, artifact["sha256"])
        self.assert_quick_unknowns(imported.artifact(artifact["sha256"]))
        apps = engine.build_apps(
            [artifact], ArtifactResults(store), None, self.limits, "quick", store
        )
        report = {"apps": apps, "stages": []}
        native = json.loads("".join(json_chunks(report)))
        for candidate in (report, native):
            self.assert_quick_unknowns(
                {"stages": query(candidate, "coverage")["items"]}
            )

    def test_skipped_binary_discovery_does_not_report_incompleteness(self):
        with patch.object(
            binary,
            "decode_method_bodies",
            side_effect=AssertionError("Unexpected body decoding"),
        ):
            result = binary.dex_index(
                privacy_dex([sensitive()]),
                self.limits,
                Budget(self.limits),
                inspect_code=False,
            )
        self.assertIsNone(result["definition_inventory_complete"])
        self.assertIsNone(result["reference_scan_complete"])
        self.assertEqual(result["scanned_methods"], 0)

    def test_executed_empty_inventory_still_reports_known_zero(self):
        artifact = self.artifact({"classes.dex": privacy_dex([])})
        for mode in ("standard", "decompile"):
            with self.subTest(mode=mode):
                result = engine.analyze_artifact(
                    artifact, self.limits, mode, self.cancel
                )
                inventory = self.stages(result)["dex_definition_inventory"]
                self.assertEqual(inventory["status"], "COMPLETE")
                self.assertEqual(
                    inventory["metrics"],
                    {
                        "definitions": 0,
                        "unique_identities": 0,
                        "duplicate_identities": 0,
                        "complete": True,
                    },
                )
                references = self.stages(result)["dex_references"]
                self.assertEqual(references["metrics"]["methods"], 0)
                self.assertTrue(references["metrics"]["scan_complete"])

    def test_duplicate_dex_members_are_rejected_before_any_discovery(self):
        first = privacy_dex([sensitive()])
        second = privacy_dex(ordinary(2))
        for mode in ("quick", "standard", "decompile"):
            for name in ("classes.dex", "nested/classes.dex"):
                for contents in (first, second):
                    with self.subTest(
                        mode=mode, entry=name, same_contents=contents == first
                    ):
                        artifact = self.artifact({name: first}, (name, contents))
                        cache = self.root / "duplicate-cache"
                        with patch.object(
                            engine,
                            "dex_index",
                            side_effect=AssertionError("Unexpected DEX discovery"),
                        ) as index:
                            result = engine.analyze_artifact(
                                artifact, self.limits, mode, self.cancel, cache
                            )
                        self.assertEqual(index.call_count, 0)
                        self.assertEqual(artifact_status(result), "FAILED")
                        self.assertIn("Duplicate archive", str(result["stages"]))
                        self.assertEqual(result["methods"], [])
                        self.assertEqual(result["statistics"]["bytes_read"], 0)
                        self.assertIsNone(result["manifest"])
                        self.assertFalse(result["definition_summary"]["complete"])
                        self.assertFalse(cache.exists())

    def test_rejected_duplicate_artifact_is_not_a_reusable_checkpoint(self):
        data = privacy_dex([sensitive()])
        artifact = self.artifact(
            {"classes.dex": data}, ("classes.dex", privacy_dex(ordinary(2)))
        )
        parsed = engine.analyze_artifact(artifact, self.limits, "standard", self.cancel)
        store = AnalysisStore(self.root / "failed.sqlite3")
        self.addCleanup(store.close)
        store.save_artifact(artifact["sha256"], parsed)
        restored = store.artifact(artifact["sha256"])
        self.assertEqual(artifact_status(restored), "FAILED")
        self.assertFalse(restored["methods"])
        for retry in (False, True):
            self.assertFalse(
                store.reusable(artifact["sha256"], parsed["cache_key"], retry)
            )

    def test_distinct_full_paths_keep_independent_dex_bodies(self):
        artifact = self.artifact(
            {
                "classes.dex": privacy_dex([sensitive()]),
                "nested/classes.dex": privacy_dex(ordinary(1)),
            }
        )
        result = engine.analyze_artifact(artifact, self.limits, "standard", self.cancel)
        self.assertEqual(len(result["methods"]), 2)
        methods = {item["entry"]: item for item in result["methods"]}
        self.assertEqual(methods["classes.dex"]["signature"], ROOT_METHOD)
        self.assertEqual(
            methods["nested/classes.dex"]["signature"], ordinary(1)[0]["signature"]
        )
        self.assertEqual(len(methods["nested/classes.dex"]["instructions"]), 1)
        self.assertGreater(len(methods["classes.dex"]["instructions"]), 1)
        self.assertEqual(result["statistics"]["dex_files"], 2)
