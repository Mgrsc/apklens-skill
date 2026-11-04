import base64
import copy
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from privacy_fixtures import ROOT_METHOD, privacy_dex
from support import make_apk
from test_analysis_quality import application, report_for
from test_method_coverage import ordinary, sensitive

from scripts.static_analysis import dataflow, dex_ir, engine, method_selection, reports
from scripts.static_analysis.common import (
    Budget,
    BudgetExceeded,
    Cancelled,
    Limits,
    MemoryBudgetExceeded,
    snapshot_file,
    stage,
)
from scripts.static_analysis.facts import artifact_state
from scripts.static_analysis.method_selection import (
    DefinitionIndex,
    definition_digest,
    definition_occurrences,
)
from scripts.static_analysis.storage import (
    AnalysisStore,
    ArtifactResults,
    artifact_status,
)


class QualityFollowupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()
        self.serial = 0

    def artifact(self, entries):
        self.serial += 1
        return snapshot_file(
            make_apk(self.root / f"sample-{self.serial}.apk", entries=entries),
            self.root / "artifacts",
            self.limits,
            self.cancel,
        )

    def parsed(self, entries):
        artifact = self.artifact(entries)
        return artifact, engine.analyze_artifact(
            artifact, self.limits, "standard", self.cancel
        )

    def test_definition_summary_is_compact_and_preserves_duplicate_membership(self):
        index = DefinitionIndex(self.limits, Budget(self.limits))
        for number in range(6000):
            index.add(definition_digest(f"Lsample/Definition{number};->run()V"))
        duplicate = definition_digest("Lsample/Definition0;->run()V")
        index.add(duplicate)
        summary = index.summary(True)
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["duplicates"], [sorted(index.counts).index(duplicate)])
        self.assertEqual(len(base64.b64decode(summary["identities"])), 6000 * 32)
        self.assertLess(len(json.dumps(summary)), 6000 * 44)

    def test_artifact_summary_round_trips_through_store_and_cache(self):
        artifact, parsed = self.parsed({"classes.dex": privacy_dex([sensitive()])})
        self.assertNotIn("definition_counts", parsed)
        self.assertNotIn("definition_identities_truncated", parsed)
        self.assertNotIn("definition_inventory_complete", parsed)
        self.assertTrue(parsed["definition_summary"]["complete"])
        self.assertEqual(parsed["cache"]["key"], parsed["cache_key"])
        store = AnalysisStore(self.root / "analysis.sqlite3")
        self.addCleanup(store.close)
        store.save_artifact(artifact["sha256"], parsed)
        stored = store.artifact(artifact["sha256"])
        self.assertEqual(stored["definition_summary"], parsed["definition_summary"])
        cache = self.root / "cached.json"
        engine.cache_write(cache, parsed)
        self.assertEqual(
            engine.cache_read(cache)["definition_summary"], parsed["definition_summary"]
        )
        cache_directory = self.root / "cache"
        engine.analyze_artifact(
            artifact, self.limits, "standard", self.cancel, cache_directory
        )
        cached = engine.analyze_artifact(
            artifact, self.limits, "standard", self.cancel, cache_directory
        )
        self.assertTrue(cached["cache"]["hit"])
        self.assertEqual(cached["cache"]["key"], cached["cache_key"])
        self.assertEqual(cached["definition_summary"], parsed["definition_summary"])
        apps = engine.build_apps(
            [artifact], ArtifactResults(store), None, self.limits, "standard", store
        )
        self.assertTrue(
            any(
                item["type"] == "privacy_transmission_path"
                for item in apps[0]["findings"]
            )
        )

    def test_singleton_in_other_split_cannot_be_hidden_by_body_selection(self):
        with patch.object(dex_ir, "MAX_INDEXED_METHODS", 1):
            first, first_result = self.parsed(
                {"classes.dex": privacy_dex([sensitive()])}
            )
            second, second_result = self.parsed(
                {
                    "classes.dex": privacy_dex(
                        [
                            sensitive(),
                            sensitive(
                                "Laaa/Main;->run(Landroid/telephony/TelephonyManager;)V"
                            ),
                        ]
                    )
                }
            )
        self.assertFalse(
            any(item["signature"] == ROOT_METHOD for item in second_result["methods"])
        )
        apps = engine.build_apps(
            [first, second],
            {first["sha256"]: first_result, second["sha256"]: second_result},
            None,
            self.limits,
            "standard",
        )
        paths = [
            item
            for item in apps[0]["findings"]
            if item["type"] == "privacy_transmission_path"
        ]
        self.assertFalse(
            any(item["evidence"][0]["method"] == ROOT_METHOD for item in paths)
        )
        self.assertTrue(
            any(item["evidence"][0]["method"].startswith("Laaa/") for item in paths)
        )

    def test_summary_membership_is_exact_and_duplicate_storage_is_bounded(self):
        index = DefinitionIndex(self.limits, Budget(self.limits))
        digests = [
            definition_digest(f"Lsample/Definition{number};->run()V")
            for number in range(6000)
        ]
        for digest in digests:
            index.add(digest, 2)
        summary = index.summary(True)
        missing = definition_digest("Lsample/Missing;->run()V")
        counts = dict(
            definition_occurrences(summary, [*digests, missing], Budget(self.limits))
        )
        self.assertEqual(counts, {**dict.fromkeys(digests, 2), missing: 0})
        self.assertLess(len(json.dumps(summary)), 6000 * 50)

    def test_invalid_summaries_defer_without_hiding_retained_candidates(self):
        _, parsed = self.parsed({"classes.dex": privacy_dex([sensitive()])})
        original = parsed["definition_summary"]
        variants = [
            {**original, "identities": "!"},
            {**original, "identities": base64.b64encode(b"short").decode()},
            {**original, "identities": original["identities"] + original["identities"]},
            {**original, "duplicates": [-1]},
            {**original, "duplicates": [True]},
            {**original, "duplicates": [0, 0]},
            {**original, "duplicates": [1]},
            {**original, "duplicates": None},
            {**original, "identities": "", "duplicates": []},
            [],
        ]
        for summary in variants:
            with self.subTest(summary=summary):
                artifact = {**parsed, "definition_summary": summary}
                flows, coverage = dataflow.analyze_dataflow(
                    parsed["methods"], self.limits, definition_summaries=[artifact]
                )
                self.assertEqual(flows, [])
                self.assertTrue(coverage[0]["metrics"]["interpretation_deferred"])
                self.assertGreater(coverage[0]["metrics"]["definitions_considered"], 0)
                self.assertFalse(
                    coverage[0]["metrics"]["definition_inventory"][0]["complete"]
                )

    def test_inventory_validation_preserves_global_stop_semantics(self):
        _, parsed = self.parsed({"classes.dex": privacy_dex([sensitive()])})
        for error in (
            Cancelled("Stopped"),
            MemoryBudgetExceeded("Memory limit"),
            BudgetExceeded("Time limit"),
        ):
            with self.subTest(error=type(error).__name__):
                analyzer = dataflow.Analyzer(
                    parsed["methods"], self.limits, definition_summaries=[parsed]
                )
                with patch.object(
                    dataflow, "definition_occurrences", side_effect=error
                ):
                    if isinstance(error, (Cancelled, MemoryBudgetExceeded)):
                        with self.assertRaises(type(error)):
                            analyzer.run()
                    else:
                        flows, coverage = analyzer.run()
                        self.assertEqual(flows, [])
                        self.assertIn("Time limit", json.dumps(coverage))
                        self.assertEqual(
                            coverage[0]["metrics"]["roots_locally_truncated"], 0
                        )

    def test_legacy_identity_summaries_are_read_without_mutation(self):
        _, parsed = self.parsed({"classes.dex": privacy_dex([sensitive()])})
        legacy = copy.deepcopy(parsed)
        del legacy["definition_summary"]
        legacy["definition_counts"] = {definition_digest(ROOT_METHOD): 1}
        legacy["definition_inventory_complete"] = True
        before = copy.deepcopy(legacy)
        flows, coverage = dataflow.analyze_dataflow(
            legacy["methods"], self.limits, definition_summaries=[legacy]
        )
        self.assertEqual(len(flows), 1)
        self.assertFalse(coverage[0]["metrics"]["interpretation_deferred"])
        self.assertEqual(legacy, before)

    def test_complete_splits_do_not_share_an_identity_admission_limit(self):
        with (
            patch.object(method_selection, "MAX_DEFINITION_IDENTITIES", 5),
            patch.object(dex_ir, "MAX_INDEXED_METHODS", 1),
        ):
            first, first_result = self.parsed(
                {"classes.dex": privacy_dex([*ordinary(4), sensitive()])}
            )
            second, second_result = self.parsed(
                {
                    "classes.dex": privacy_dex(
                        [
                            {
                                **item,
                                "signature": item["signature"].replace(
                                    "Llibrary/", "Lother/"
                                ),
                            }
                            for item in ordinary(4)
                        ]
                    )
                }
            )
            apps = engine.build_apps(
                [first, second],
                {first["sha256"]: first_result, second["sha256"]: second_result},
                None,
                self.limits,
                "standard",
            )
        self.assertTrue(
            any(
                item["type"] == "privacy_transmission_path"
                for item in apps[0]["findings"]
            )
        )

    def test_incomplete_inventory_explains_each_artifact_after_indexing(self):
        first, first_result = self.parsed({"classes.dex": privacy_dex([sensitive()])})
        second, second_result = self.parsed({"classes.dex": b"Unsupported DEX"})
        apps = engine.build_apps(
            [first, second],
            {first["sha256"]: first_result, second["sha256"]: second_result},
            None,
            self.limits,
            "standard",
        )
        coverage = next(
            item
            for item in apps[0]["coverage"]
            if item["stage"] == "method_dataflow_E3"
        )
        self.assertFalse(
            any(
                item["type"] == "privacy_transmission_path"
                for item in apps[0]["findings"]
            )
        )
        self.assertGreater(coverage["metrics"]["definitions_considered"], 0)
        inventory = coverage["metrics"]["definition_inventory"]
        self.assertEqual(
            {item["artifact"] for item in inventory},
            {first["sha256"], second["sha256"]},
        )
        self.assertEqual(
            [item["artifact"] for item in inventory if not item["complete"]],
            [second["sha256"]],
        )
        self.assertTrue(coverage["metrics"]["interpretation_deferred"])

    def test_dex_metrics_report_actual_retained_bodies_and_reference_scan(self):
        _, parsed = self.parsed(
            {
                "classes.dex": privacy_dex(ordinary(2)),
                "classes2.dex": privacy_dex([sensitive()]),
            }
        )
        indexes = [
            item for item in parsed["stages"] if item["stage"] == "dex_structure_index"
        ]
        for item in indexes:
            retained = [
                method
                for method in parsed["methods"]
                if method["entry"] == item["source"]
            ]
            self.assertEqual(item["metrics"]["methods"], len(retained))
            self.assertEqual(item["metrics"]["method_definitions"], len(retained))
        references = [
            item for item in parsed["stages"] if item["stage"] == "dex_references"
        ]
        self.assertTrue(all(item["metrics"]["scan_complete"] for item in references))

    def test_export_reuses_summary_facts(self):
        report = report_for([application()])
        with patch.object(reports, "summary", wraps=reports.summary) as summary:
            reports.export_reports(report, self.root / "export", write_analysis=False)
        self.assertEqual(summary.call_count, 1)
        actual = (self.root / "export" / "report.md").read_text()
        self.assertEqual(actual, reports.markdown(report))

    def test_markdown_facts_preserve_json_while_escaping_backticks(self):
        report = report_for([application()])
        facts = {"value": "```\n<script>value</script>"}
        with patch.object(reports, "summary", return_value={"facts": facts}):
            text = reports.markdown(report)
        block = text.split("```json\n", 1)[1].split("\n```", 1)[0]
        self.assertEqual(json.loads(block), facts)
        self.assertNotIn("`", block)

    def test_artifact_statuses_share_empty_and_nonempty_semantics(self):
        for statuses in (
            [],
            ["COMPLETE"],
            ["PARTIAL"],
            ["FAILED"],
            ["CANCELLED", "FAILED"],
        ):
            with self.subTest(statuses=statuses):
                self.assertEqual(
                    artifact_state(set(statuses)),
                    artifact_status(
                        {"stages": (stage("sample", status) for status in statuses)}
                    ),
                )

    def test_default_method_cache_retains_small_helpers_with_metadata(self):
        artifact, parsed = self.parsed({"classes.dex": privacy_dex(ordinary(64))})
        store = AnalysisStore(self.root / "cache.sqlite3")
        self.addCleanup(store.close)
        store.save_artifact(artifact["sha256"], parsed)
        store.merge("app", "methods", parsed["methods"], self.limits)
        records = store.records("app", "app", "methods")
        analyzer = dataflow.Analyzer(records, self.limits)
        analyzer.index = {
            item["signature"]: [(position, item["id"])]
            for position, item in enumerate(records)
        }
        with patch.object(
            analyzer.methods, "page", wraps=analyzer.methods.page
        ) as page:
            for _ in range(2):
                for signature in analyzer.index:
                    analyzer.lookup(signature)
        self.assertEqual(page.call_count, 64)
        self.assertEqual(len(analyzer.method_cache), 64)
        self.assertLessEqual(
            analyzer.method_cache_bytes, dataflow.MAX_METHOD_CACHE_BYTES
        )
