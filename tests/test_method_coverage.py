import copy
import json
import struct
import tempfile
import threading
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from privacy_fixtures import IDENTITY, ROOT_METHOD, privacy_dex, transmission
from support import make_apk
from test_privacy_regressions import checksummed

from scripts.static_analysis import dataflow, dex_ir, engine
from scripts.static_analysis.binary import dex_index
from scripts.static_analysis.common import (
    Budget,
    BudgetExceeded,
    Cancelled,
    Limits,
    MemoryBudgetExceeded,
    snapshot_file,
)
from scripts.static_analysis.method_selection import definition_digest


def sensitive(signature=ROOT_METHOD):
    return {
        "signature": signature,
        "code": [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            *transmission(),
            0x0E,
        ],
    }


def ordinary(count, size=1):
    return [
        {
            "signature": f"Llibrary/Class{index:05};->run()V",
            "code": [0] * (size - 1) + [0x0E],
        }
        for index in range(count)
    ]


def method_records(definitions):
    limits = Limits()
    index = dex_index(privacy_dex(definitions), limits, Budget(limits))
    return [
        {"id": str(number), "artifact": "artifact", "entry": "classes.dex", **method}
        for number, method in enumerate(index["bodies"])
    ]


class MethodCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()

    def parse(self, definitions, limits=None):
        limits = limits or self.limits
        return dex_index(privacy_dex(definitions), limits, Budget(limits))

    def artifact(self, entries):
        path = make_apk(self.root / "sample.apk", entries=entries)
        return snapshot_file(path, self.root / "artifacts", self.limits, self.cancel)

    def test_late_sensitive_body_survives_instruction_pressure(self):
        index = self.parse(
            [*ordinary(12, 13), sensitive()], replace(self.limits, max_references=100)
        )
        body = next(
            item for item in index["bodies"] if item["signature"] == ROOT_METHOD
        )
        self.assertTrue(body["instructions"])
        self.assertFalse(body.get("gap"))
        methods = [
            {"id": str(number), "artifact": "artifact", "entry": "classes.dex", **item}
            for number, item in enumerate(index["bodies"])
        ]
        flows, _ = dataflow.analyze_dataflow(methods, self.limits)
        self.assertEqual(len(flows), 1)

    def test_late_sensitive_body_survives_method_limit(self):
        with patch.object(dex_ir, "MAX_INDEXED_METHODS", 4):
            index = self.parse([*ordinary(12), sensitive()])
        self.assertEqual(len(index["bodies"]), 4)
        self.assertTrue(
            any(
                item["signature"] == ROOT_METHOD and item["instructions"]
                for item in index["bodies"]
            )
        )
        self.assertGreater(index["selection_metrics"]["body_budget_omitted"], 0)

    def test_full_candidate_pool_accepts_later_sensitive_method(self):
        index = self.parse(
            [*ordinary(30), sensitive()], replace(self.limits, max_results=2)
        )
        self.assertTrue(
            any(item["signature"] == ROOT_METHOD for item in index["bodies"])
        )
        self.assertGreater(index["selection_metrics"]["candidate_pool_omitted"], 0)
        self.assertLessEqual(index["selection_metrics"]["candidate_pool_retained"], 2)

    def test_later_dex_receives_body_budget_and_reads_are_counted(self):
        first, second = privacy_dex(ordinary(12)), privacy_dex([sensitive()])
        artifact = self.artifact({"classes.dex": first, "classes2.dex": second})
        with patch.object(dex_ir, "MAX_INDEXED_METHODS", 4):
            result = engine.analyze_artifact(
                artifact, self.limits, "standard", self.cancel
            )
        self.assertTrue(
            any(
                item["entry"] == "classes2.dex"
                and item["signature"] == ROOT_METHOD
                and item["instructions"]
                for item in result["methods"]
            )
        )
        metrics = next(
            item["metrics"]
            for item in result["stages"]
            if item["stage"] == "dex_body_selection"
        )
        self.assertEqual(metrics["definitions_considered"], 13)
        self.assertEqual(
            result["statistics"]["bytes_read"],
            result["statistics"]["unique_bytes_read"] + metrics["second_pass_bytes"],
        )
        self.assertEqual(metrics["second_pass_bytes"], len(first) + len(second))

    def test_second_pass_does_not_bypass_archive_read_limit(self):
        artifact = self.artifact({"classes.dex": privacy_dex([sensitive()])})
        with zipfile.ZipFile(artifact["path"]) as archive:
            total = sum(item.file_size for item in archive.infolist())
        result = engine.analyze_artifact(
            artifact,
            replace(self.limits, max_total_bytes=total),
            "standard",
            self.cancel,
        )
        self.assertEqual(result["methods"], [])
        body_stage = next(
            item for item in result["stages"] if item["stage"] == "dex_body_selection"
        )
        self.assertEqual(body_stage["status"], "PARTIAL")
        self.assertEqual(body_stage["metrics"]["retained_methods"], 0)
        self.assertEqual(result["statistics"]["bytes_read"], total)

    def test_one_expensive_root_does_not_starve_later_sensitive_root(self):
        helper = "Llibrary/Worker;->work()V"
        first = "Lsample/A;->run(Landroid/telephony/TelephonyManager;)V"
        second = "Lsample/Z;->run(Landroid/telephony/TelephonyManager;)V"
        methods = method_records(
            [
                {
                    "signature": first,
                    "code": [
                        ("invoke", IDENTITY, [7], False),
                        ("result", 0),
                        ("invoke", helper, [], True),
                        0x0E,
                    ],
                },
                {"signature": helper, "code": [0] * 100 + [0x0E]},
                sensitive(second),
            ]
        )
        analyzer = dataflow.Analyzer(methods, self.limits)
        roots = []
        execute = analyzer.execute

        def observed(method, arguments, parent, stack=()):
            if not stack:
                roots.append(method["signature"])
            return execute(method, arguments, parent, stack)

        with (
            patch.object(dataflow, "MAX_ROOT_STEPS", 32),
            patch.object(dataflow, "MAX_APP_STEPS", 100),
            patch.object(analyzer, "execute", side_effect=observed),
        ):
            flows, coverage = analyzer.run()
        self.assertEqual(roots[0], first)
        self.assertIn(second, roots)
        self.assertTrue(
            any(
                any(item["method"] == second for item in flow["evidence"])
                for flow in flows
            )
        )
        self.assertGreater(coverage[0]["metrics"]["roots_locally_truncated"], 0)
        self.assertEqual(coverage[0]["status"], "PARTIAL")

    def test_application_index_admits_late_sensitive_method(self):
        methods = method_records([*ordinary(25), sensitive()])
        analyzer = dataflow.Analyzer(methods, self.limits)
        with patch.object(dataflow, "MAX_APP_METHODS", 3):
            flows, coverage = analyzer.run()
        self.assertIn(ROOT_METHOD, analyzer.index)
        self.assertEqual(len(flows), 1)
        self.assertEqual(coverage[0]["metrics"]["definitions_considered"], 26)
        self.assertEqual(coverage[0]["metrics"]["index_omitted"], 23)

    def test_duplicate_outside_admission_cannot_become_unique_path(self):
        methods = method_records([sensitive()])
        duplicate = copy.deepcopy(methods[0])
        duplicate.update(id="duplicate", entry="classes2.dex")
        analyzer = dataflow.Analyzer([*methods, duplicate], self.limits)
        with patch.object(dataflow, "MAX_APP_METHODS", 1):
            flows, coverage = analyzer.run()
        self.assertEqual(flows, [])
        self.assertIn("Ambiguous duplicate", json.dumps(coverage))

    def test_duplicate_outside_artifact_body_selection_remains_ambiguous(self):
        artifact = self.artifact(
            {
                "classes.dex": privacy_dex([sensitive()]),
                "classes2.dex": privacy_dex([sensitive()]),
            }
        )
        with patch.object(dex_ir, "MAX_INDEXED_METHODS", 1):
            result = engine.analyze_artifact(
                artifact, self.limits, "standard", self.cancel
            )
        self.assertEqual(len(result["methods"]), 1)
        apps = engine.build_apps(
            [artifact], {artifact["sha256"]: result}, None, self.limits, "standard"
        )
        self.assertFalse(
            any(
                item["type"] == "privacy_transmission_path"
                for item in apps[0]["findings"]
            )
        )

    def test_global_stops_are_not_swallowed_as_root_truncation(self):
        methods = method_records([sensitive()])
        for counts, complete in (({}, False), (None, True)):
            analyzer = dataflow.Analyzer(
                methods,
                self.limits,
                definition_summaries=[
                    {
                        "sha256": "artifact",
                        "definition_counts": counts,
                        "definition_inventory_complete": complete,
                    }
                ],
            )
            flows, coverage = analyzer.run()
            self.assertEqual(flows, [])
            self.assertIn("identity coverage is incomplete", json.dumps(coverage))
        analyzer = dataflow.Analyzer(
            methods,
            self.limits,
            definition_summaries=[
                {
                    "sha256": "artifact",
                    "definition_counts": {definition_digest(ROOT_METHOD): 2},
                    "definition_inventory_complete": True,
                }
            ],
        )
        self.assertEqual(analyzer.run()[0], [])
        for error in (Cancelled("cancelled"), MemoryBudgetExceeded("memory")):
            with self.subTest(error=type(error).__name__):
                analyzer = dataflow.Analyzer(method_records([sensitive()]), self.limits)
                with (
                    patch.object(analyzer, "execute", side_effect=error),
                    self.assertRaises(type(error)),
                ):
                    analyzer.run()
        analyzer = dataflow.Analyzer(method_records([sensitive()]), self.limits)
        with patch.object(
            analyzer,
            "execute",
            side_effect=BudgetExceeded("Artifact time budget exceeded"),
        ):
            _, coverage = analyzer.run()
        self.assertEqual(coverage[0]["status"], "PARTIAL")
        self.assertEqual(coverage[0]["metrics"]["roots_locally_truncated"], 0)

    def test_incomplete_dex_discovery_cannot_establish_unique_application_methods(self):
        artifact = self.artifact(
            {
                "classes.dex": b"Unsupported DEX",
                "classes2.dex": privacy_dex([sensitive()]),
            }
        )
        result = engine.analyze_artifact(artifact, self.limits, "standard", self.cancel)
        self.assertTrue(result["methods"])
        self.assertFalse(result["definition_summary"]["complete"])
        apps = engine.build_apps(
            [artifact], {artifact["sha256"]: result}, None, self.limits, "standard"
        )
        self.assertFalse(
            any(
                item["type"] == "privacy_transmission_path"
                for item in apps[0]["findings"]
            )
        )
        self.assertIn(
            "identity coverage is incomplete", json.dumps(apps[0]["coverage"])
        )

    def test_reference_limit_preserves_later_definitions(self):
        definitions = [
            sensitive("Lsample/Main;->early(Landroid/telephony/TelephonyManager;)V"),
            sensitive(),
            {"signature": "Lsample/Main;->later()V", "code": [0x0E]},
        ]
        index = self.parse(definitions, replace(self.limits, max_references=3))
        self.assertTrue(index["definition_inventory_complete"])
        self.assertFalse(index["reference_scan_complete"])
        self.assertEqual(index["selection_metrics"]["definitions_considered"], 3)
        self.assertIn("DEX reference count exceeds the budget", index["gaps"])

    def test_bad_body_does_not_skip_later_definitions_in_same_class(self):
        first = {"signature": "Lsample/Main;->broken()V", "code": [0x0E]}
        data = privacy_dex([first, sensitive()])
        original = dex_index(data, self.limits, Budget(self.limits))
        broken = bytearray(data)
        struct.pack_into("<H", broken, original["bodies"][0]["code_offset"] + 16, 0x18)
        index = dex_index(checksummed(broken), self.limits, Budget(self.limits))
        self.assertTrue(index["definition_inventory_complete"])
        self.assertIn("gap", index["bodies"][0])
        self.assertTrue(
            next(item for item in index["bodies"] if item["signature"] == ROOT_METHOD)[
                "instructions"
            ]
        )

    def test_gap_occurrences_continue_after_display_budget(self):
        analyzer = dataflow.Analyzer([], self.limits)
        for index in range(300):
            analyzer.gap(
                "Unmodeled external invocation",
                dataflow.Node(
                    "artifact",
                    "classes.dex",
                    f"Lsample/{index};->run()V",
                    0,
                    "call",
                    "target",
                ),
            )
        self.assertEqual(analyzer.gap_counts["Unmodeled external invocation"], 300)
        _, coverage = analyzer.run()
        self.assertTrue(coverage[0]["metrics"]["gap_samples_truncated"])
        self.assertLessEqual(len(analyzer.gaps), dataflow.MAX_GAPS + 1)

    def test_cancellation_during_body_decoding_remains_cancelled(self):
        artifact = self.artifact({"classes.dex": privacy_dex([sensitive()])})
        with patch.object(
            engine,
            "decode_method_bodies",
            side_effect=Cancelled("Body decoding cancelled"),
        ):
            result = engine.analyze_artifact(
                artifact, self.limits, "standard", self.cancel
            )
        self.assertTrue(any(item["status"] == "CANCELLED" for item in result["stages"]))
        self.assertEqual(result["methods"], [])
