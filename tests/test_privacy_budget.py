import copy
import json
import tempfile
import threading
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from privacy_fixtures import IDENTITY, privacy_dex, transmission
from support import make_apk

from scripts.static_analysis import dataflow, engine
from scripts.static_analysis.binary import dex_index
from scripts.static_analysis.common import Budget, Limits, json_chunks, snapshot_file
from scripts.static_analysis.reports import query, summary
from scripts.static_analysis.storage import AnalysisStore, ArtifactResults


def branching_definition(count, owner="Lsample/A;"):
    registers = max(8, count + 3)
    receiver = registers - count - 1
    code = [("invoke", IDENTITY, [receiver], False), ("result", 0)]
    for index in range(count):
        code.extend([(receiver + 1 + index) << 8 | 0x38, 3, 0])
    return {
        "signature": owner
        + "->run(Landroid/telephony/TelephonyManager;"
        + "I" * count
        + ")V",
        "registers": registers,
        "code": [*code, *transmission(), 0x0E],
    }


class PagedMethods:
    def __init__(self, methods):
        self.methods = methods
        self.reads = Counter()

    def __iter__(self):
        return iter(copy.deepcopy(self.methods))

    def page(self, *, identity):
        self.reads[identity] += 1
        return iter(
            copy.deepcopy([item for item in self.methods if item["id"] == identity])
        )


class PrivacyBudgetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()

    def methods(self, definitions):
        index = dex_index(
            privacy_dex(definitions), self.limits, Budget(self.limits, self.cancel)
        )
        self.assertEqual(index["gaps"], [])
        return [
            {"id": str(i), "artifact": "artifact", "entry": "classes.dex", **body}
            for i, body in enumerate(index["bodies"])
        ]

    def node(self, name="A", offset=0):
        return dataflow.Node(
            "artifact", "classes.dex", f"Lsample/{name};->run()V", offset, "call", name
        )

    def emit(self, analyzer, name="A", condition="first", endpoints=()):
        state = {"heap": {}, "files": {}, "statics": {}, "conditions": [condition]}
        analyzer.emit(
            analyzer.source("device_identifier", self.node(name)),
            self.node(name, 1),
            state,
            endpoints,
        )

    def app(self, flows):
        app = {
            "id": "app",
            "findings": copy.deepcopy(flows),
            "signals": [],
            "endpoints": [],
            "capabilities": [],
            "permissions": [],
            "manifests": [],
        }
        engine.build_findings(app)
        return app

    def test_duplicate_at_capacity_is_idempotent(self):
        analyzer = dataflow.Analyzer([], replace(self.limits, max_results=1))
        self.emit(analyzer)
        expected = copy.deepcopy(analyzer.flows)
        self.emit(analyzer)
        self.assertEqual(analyzer.flows, expected)
        self.assertEqual(analyzer.gaps, {})
        self.emit(analyzer, "B")
        self.assertEqual(analyzer.flows, expected)
        self.assertIn(
            "Dataflow result budget exceeded",
            [item["reason"] for item in analyzer.gaps.values()],
        )

    def test_default_capacity_deduplicates_all_retained_identities(self):
        analyzer = dataflow.Analyzer([], self.limits)
        for index in range(1000):
            self.emit(analyzer, str(index))
        expected = copy.deepcopy(analyzer.flows)
        for index in range(1000):
            self.emit(analyzer, str(index))
        self.assertEqual(len(analyzer.flows), 1000)
        self.assertEqual(analyzer.flows, expected)
        self.assertEqual(analyzer.gaps, {})

    def test_variant_cap_preserves_exact_boundary_and_duplicate_conditions(self):
        analyzer = dataflow.Analyzer([], self.limits)
        for condition in range(4):
            self.emit(analyzer, condition=str(condition))
        expected = copy.deepcopy(analyzer.flows)
        self.emit(analyzer, condition="0")
        self.assertEqual(analyzer.flows, expected)
        self.assertEqual(analyzer.gaps, {})
        self.emit(analyzer, condition="4")
        self.assertEqual(analyzer.flows, expected)
        self.assertEqual(len(analyzer.gaps), 1)

    def test_variants_are_bounded_and_truncation_is_located(self):
        methods = self.methods([branching_definition(5)])
        flows, coverage = dataflow.analyze_dataflow(methods, self.limits)
        self.assertEqual(len(flows), 4)
        self.assertEqual(len({tuple(item["evidence_ids"]) for item in flows}), 1)
        self.assertEqual(len({tuple(item["conditions"]) for item in flows}), 4)
        self.assertTrue(all(len(item["conditions"]) == 5 for item in flows))
        self.assertEqual({item["status"] for item in coverage}, {"PARTIAL"})
        gaps = coverage[0]["metrics"]["gaps"]
        self.assertTrue(any("variant" in item["reason"] for item in gaps))
        self.assertTrue(all(item["method"] == methods[0]["signature"] for item in gaps))
        self.assertTrue(all("instruction_offset" in item for item in gaps))

    def test_independent_path_replaces_only_a_redundant_variant(self):
        analyzer = dataflow.Analyzer([], replace(self.limits, max_results=4))
        for name in ("A", "B"):
            for condition in ("first", "second"):
                self.emit(analyzer, name, condition)
        for name in ("C", "D"):
            self.emit(analyzer, name)
        self.assertEqual(len(analyzer.flows), 4)
        self.assertEqual(
            {item["evidence"][0]["method"] for item in analyzer.flows.values()},
            {self.node(name).method for name in ("A", "B", "C", "D")},
        )
        self.assertEqual(
            {item["conditions"][0] for item in analyzer.flows.values()}, {"first"}
        )
        self.assertEqual(
            {item["method"] for item in analyzer.gaps.values()},
            {self.node("A").method, self.node("B").method},
        )
        expected = copy.deepcopy(analyzer.flows)
        self.emit(analyzer, "E")
        self.assertEqual(analyzer.flows, expected)

    def test_existing_group_cannot_displace_an_independent_path(self):
        analyzer = dataflow.Analyzer([], replace(self.limits, max_results=3))
        self.emit(analyzer, "A")
        self.emit(analyzer, "A", "second")
        self.emit(analyzer, "B")
        expected = copy.deepcopy(analyzer.flows)
        self.emit(analyzer, "B", "second")
        self.assertEqual(analyzer.flows, expected)
        self.assertTrue(
            any("variant" in item["reason"] for item in analyzer.gaps.values())
        )
        self.assertFalse(
            any(
                item["reason"] == "Dataflow result budget exceeded"
                for item in analyzer.gaps.values()
            )
        )

    def test_truncated_source_does_not_block_other_sources(self):
        analyzer = dataflow.Analyzer([], replace(self.limits, max_results=4))
        sink = self.node("Sink")
        first = analyzer.source("device_identifier", self.node("A"))
        second = analyzer.source("installed_apps", self.node("B"))
        for index in range(4):
            analyzer.emit(first, sink, {"heap": {}, "conditions": [str(index)]})
        analyzer.emit(
            analyzer.join(first, second), sink, {"heap": {}, "conditions": ["extra"]}
        )
        self.assertEqual(len(analyzer.flows), 4)
        self.assertEqual(
            {item["data_category"] for item in analyzer.flows.values()},
            {"device_identifier", "installed_apps"},
        )

    def test_addresses_and_evidence_order_are_independent_groups(self):
        analyzer = dataflow.Analyzer([], replace(self.limits, max_results=2))
        self.emit(analyzer, endpoints=("https://first.example",))
        self.emit(analyzer, endpoints=("https://second.example",))
        self.assertEqual(len(analyzer.flows), 2)
        self.assertEqual(analyzer.gaps, {})
        self.assertEqual(
            self.app(list(analyzer.flows.values()))["priority"]["score"], 12
        )
        flows = list(analyzer.flows.values())
        flows[1]["sink"]["endpoints"] = flows[0]["sink"]["endpoints"]
        flows[1]["evidence_ids"] = list(reversed(flows[0]["evidence_ids"]))
        self.assertEqual(self.app(flows)["priority"]["score"], 12)

    def test_rejected_groups_do_not_grow_retained_indexes(self):
        analyzer = dataflow.Analyzer([], replace(self.limits, max_results=1))
        for index in range(40):
            self.emit(analyzer, str(index))
        self.assertEqual(len(analyzer.flows), 1)
        self.assertEqual(len(analyzer.flow_groups), 1)
        self.assertEqual(len(analyzer.variant_groups), 0)

    def test_branch_budget_keeps_later_method_and_preserves_conditions(self):
        methods = self.methods(
            [branching_definition(5), branching_definition(0, "Lsample/Z;")]
        )
        with patch.object(dataflow, "MAX_FLOWS", 4):
            flows, coverage = dataflow.analyze_dataflow(methods, self.limits)
        self.assertEqual(len(flows), 4)
        self.assertEqual(len({tuple(item["evidence_ids"]) for item in flows}), 2)
        self.assertEqual(coverage[0]["status"], "PARTIAL")
        for item in flows:
            count = 0 if item["evidence"][0]["method"].startswith("Lsample/Z;") else 5
            self.assertEqual(len(item["conditions"]), count)

    def test_branch_variants_do_not_inflate_priority(self):
        for branches in (0, 1, 5):
            with self.subTest(branches=branches):
                flows, _ = dataflow.analyze_dataflow(
                    self.methods([branching_definition(branches)]), self.limits
                )
                app = self.app(flows)
                self.assertEqual(app["priority"]["score"], 6)
                self.assertEqual(len(app["findings"]), min(2**branches, 4))

    def test_root_misses_skip_cache_admission(self):
        records = PagedMethods(
            self.methods(
                [
                    {"signature": f"Lsample/A;->run{i}()V", "code": [0x0E]}
                    for i in range(64)
                ]
            )
        )
        analyzer = dataflow.Analyzer(records, self.limits)
        with patch.object(
            analyzer, "cache_method", wraps=analyzer.cache_method
        ) as cache:
            _, coverage = analyzer.run()
        self.assertEqual(cache.call_count, 0)
        self.assertEqual(len(analyzer.method_cache), 0)
        self.assertEqual(sum(records.reads.values()), 64)
        self.assertEqual(coverage[0]["status"], "COMPLETE")

    def test_call_cache_and_root_hits_are_reused(self):
        for helper_first in (False, True):
            with self.subTest(helper_first=helper_first):
                helper = ("Lsample/A;" if helper_first else "Lsample/Z;") + "->help()V"
                caller_owner = "Lsample/Z;" if helper_first else "Lsample/A;"
                definitions = [
                    {"signature": helper, "code": [0] * 6 + [0x0E]},
                    {
                        "signature": caller_owner + "->call()V",
                        "code": [
                            ("invoke", helper, [], True),
                            ("invoke", helper, [], True),
                            0x0E,
                        ],
                    },
                ]
                if not helper_first:
                    definitions.reverse()
                records = PagedMethods(self.methods(definitions))
                analyzer = dataflow.Analyzer(records, self.limits)
                with patch.object(
                    analyzer, "cache_method", wraps=analyzer.cache_method
                ) as cache:
                    _, coverage = analyzer.run()
                identity = next(
                    item["id"]
                    for item in records.methods
                    if item["signature"] == helper
                )
                self.assertEqual(cache.call_count, 1)
                self.assertEqual(
                    next(iter(analyzer.index)),
                    helper if helper_first else caller_owner + "->call()V",
                )
                self.assertEqual(records.reads[identity], 2 if helper_first else 1)
                self.assertEqual(coverage[0]["status"], "COMPLETE")

    def store(self, name):
        store = AnalysisStore(self.root / name, cancel=self.cancel)
        self.addCleanup(store.close)
        return store

    def artifact(self):
        return snapshot_file(
            make_apk(
                self.root / "branches.apk",
                entries={"classes.dex": privacy_dex([branching_definition(5)])},
            ),
            self.root / "artifacts",
            self.limits,
            self.cancel,
        )

    def test_json_and_sqlite_keep_variant_queries_and_summary_consistent(self):
        artifact = self.artifact()
        parsed = engine.analyze_artifact(artifact, self.limits, "standard", self.cancel)
        store = self.store("analysis.sqlite3")
        store.save_artifact(artifact["sha256"], parsed)
        apps = engine.build_apps(
            [artifact], ArtifactResults(store), None, self.limits, "standard", store
        )
        report = {
            "schema_version": 1,
            "engine_version": engine.ENGINE_VERSION,
            "run": {},
            "totals": {},
            "limitations": [],
            "apps": apps,
        }
        native = json.loads("".join(json_chunks(report)))
        memory = {
            **report,
            "apps": engine.build_apps(
                [artifact], {artifact["sha256"]: parsed}, None, self.limits, "standard"
            ),
        }
        self.assertEqual(summary(report), summary(native))
        self.assertEqual(summary(report), summary(memory))
        for section in ("findings", "evidence", "methods", "coverage"):
            expected = query(native, section)
            self.assertEqual(query(report, section), expected)
            self.assertEqual(query(memory, section), expected)
            for identity in (None, expected["items"][0].get("id"), "missing"):
                for offset in (0, 1):
                    self.assertEqual(
                        query(
                            report, section, identity=identity, offset=offset, limit=1
                        ),
                        query(
                            native, section, identity=identity, offset=offset, limit=1
                        ),
                    )
        flows = [
            item
            for item in query(native, "findings")["items"]
            if item["type"] == "privacy_transmission_path"
        ]
        self.assertEqual(len(flows), 4)
        self.assertEqual(len({tuple(item["conditions"]) for item in flows}), 4)
        self.assertEqual(
            set(flows[0]) - {"app_id", "package", "user"},
            {
                "id",
                "type",
                "evidence_level",
                "data_category",
                "relation",
                "evidence_ids",
                "evidence",
                "conditions",
                "sink",
                "meaning",
            },
        )

    def test_previous_budget_semantics_invalidate_cache_and_resume(self):
        artifact = self.artifact()
        cache = self.root / "cache"
        source = self.store("source.sqlite3")
        with (
            patch.object(engine, "ENGINE_VERSION", "1.1.1"),
            patch.object(engine, "MODEL_VERSION", "2"),
        ):
            old = engine.analyze_artifact(
                artifact, self.limits, "standard", self.cancel, cache
            )
            source.save_artifact(artifact["sha256"], old)
        before = (self.root / "source.sqlite3").read_bytes()
        target = self.store("target.sqlite3")
        with patch.object(engine, "dex_index", wraps=engine.dex_index) as parse:
            results = engine.analyze_many(
                [artifact],
                self.limits,
                "standard",
                self.cancel,
                1,
                cache,
                lambda event: None,
                store=target,
                resume_store=source,
            )
        self.assertEqual(parse.call_count, 2)
        self.assertFalse(parse.call_args_list[-1].kwargs["inspect_code"])
        key = engine.cache_key(artifact["sha256"], self.limits, "standard")
        self.assertNotEqual(old["cache_key"], key)
        self.assertEqual(results[artifact["sha256"]]["cache_key"], key)
        self.assertEqual((self.root / "source.sqlite3").read_bytes(), before)
        app = engine.build_apps(
            [artifact], results, None, self.limits, "standard", target
        )[0]
        flows = [
            item
            for item in app["findings"]
            if item["type"] == "privacy_transmission_path"
        ]
        self.assertEqual(len(flows), 4)
