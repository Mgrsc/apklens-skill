import copy
import hashlib
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from support import make_apk, make_dex

from scripts.static_analysis import storage
from scripts.static_analysis.common import (
    MEMORY_BUDGET_MESSAGE,
    AnalysisError,
    Budget,
    Cancelled,
    JsonRecords,
    Limits,
    MemoryBudgetExceeded,
    atomic_json,
    json_chunks,
    snapshot_file,
)
from scripts.static_analysis.endpoints import EndpointCollector
from scripts.static_analysis.engine import analyze_artifact, analyze_many, cache_key
from scripts.static_analysis.reports import (
    SECTIONS,
    markdown,
    query,
    section_rows,
    summary,
)
from scripts.static_analysis.rules import SDK_RULES, sdk_matches
from scripts.static_analysis.storage import AnalysisStore, FindingIds


class PerformanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()

    def artifact(self):
        return snapshot_file(
            make_apk(self.root / "input.apk", entries={"classes.dex": make_dex()}),
            self.root / "artifacts",
            self.limits,
            self.cancel,
        )

    def store(self, name="analysis.sqlite3", **options):
        store = AnalysisStore(self.root / name, **options)
        self.addCleanup(store.close)
        return store

    def test_transient_memory_signal_in_dex_instruction_stops_and_is_not_reused(self):
        class OneShotMemoryBudget(Budget):
            raised = False

            def check(self):
                caller = sys._getframe(1)
                if (
                    not self.raised
                    and caller.f_code.co_name == "dex_index"
                    and caller.f_locals.get("cursor") == 0
                ):
                    self.raised = True
                    raise MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE)
                super().check()

        artifact = self.artifact()
        store = self.store()
        with patch("scripts.static_analysis.engine.Budget", OneShotMemoryBudget):
            results = analyze_many(
                [artifact],
                self.limits,
                "standard",
                self.cancel,
                1,
                None,
                lambda event: None,
                store=store,
            )
        self.assertTrue(self.cancel.is_set())
        self.assertTrue(results[artifact["sha256"]]["resource_limited"])
        self.assertFalse(
            store.reusable(
                artifact["sha256"],
                cache_key(artifact["sha256"], self.limits, "standard"),
                False,
            )
        )

    def test_dex_fallback_propagates_transient_memory_and_cancellation(self):
        artifact = self.artifact()
        for error in (
            MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE),
            Cancelled("Stopped"),
        ):
            with self.subTest(error=type(error).__name__):
                cancel = threading.Event()
                with patch(
                    "scripts.static_analysis.engine.dex_index", side_effect=error
                ):
                    result = analyze_artifact(artifact, self.limits, "standard", cancel)
                if isinstance(error, MemoryBudgetExceeded):
                    self.assertTrue(result["resource_limited"])
                    self.assertTrue(cancel.is_set())
                else:
                    self.assertTrue(
                        any(item["status"] == "CANCELLED" for item in result["stages"])
                    )
                self.assertFalse(
                    any(item["stage"] == "dex_structure" for item in result["stages"])
                )

    def test_legacy_memory_gap_retries_without_invalidating_ordinary_partial(self):
        artifact = self.artifact()
        result = analyze_artifact(artifact, self.limits, "standard", threading.Event())
        store = self.store()
        for stage_name in ("dex_structure", "dex_references", "endpoint_extraction"):
            for reason in (MEMORY_BUDGET_MESSAGE, "DEX invocation target is invalid"):
                with self.subTest(stage=stage_name, reason=reason):
                    value = copy.deepcopy(result)
                    value["stages"].append(
                        {"stage": stage_name, "status": "PARTIAL", "reason": reason}
                    )
                    store.save_artifact(artifact["sha256"], value)
                    reusable = store.reusable(
                        artifact["sha256"], result["cache_key"], False
                    )
                    self.assertEqual(
                        reusable,
                        not (
                            stage_name.startswith("dex_")
                            and reason == MEMORY_BUDGET_MESSAGE
                        ),
                    )

    def fixture(self, app_count=3, record_count=8, split_count=1):
        from benchmarks.performance import build_fixture

        store, report, _ = build_fixture(
            self.root, app_count, record_count, split_count
        )
        self.addCleanup(store.close)
        return store, report

    def native_report(self, report):
        return json.loads("".join(json_chunks(report)))

    def decoded(self, operation):
        counts = []
        original_loads = json.loads

        def audited(payload, *args, **kwargs):
            value = original_loads(payload, *args, **kwargs)
            if isinstance(value, dict) and any(
                key in value for key in ("evidence", "evidence_ids", "stage")
            ):
                counts.append(value)
            return value

        with patch.object(
            storage, "json", SimpleNamespace(loads=audited, dumps=json.dumps)
        ):
            result = operation()
        return result, counts

    def test_queries_match_legacy_across_sections_filters_and_page_boundaries(self):
        _, report = self.fixture()
        report["stages"] = [
            {"stage": "run_test", "status": "PARTIAL", "reason": "Run gap"}
        ]
        legacy = self.native_report(report)
        for section in SECTIONS:
            rows = list(section_rows(legacy, section))
            identity = next((row["id"] for row in rows if row.get("id")), "absent")
            filters = (
                {},
                {"identity": identity},
                {"identity": "absent"},
                {"contains": "EVENTS"},
                {"contains": "absent"},
                {"contains": "\u00df"},
                {"identity": identity, "contains": "evidence"},
                {"package": "com.example.app1"},
                {"package": ""},
                {"package": "absent"},
            )
            for options in filters:
                for offset in (0, 1, len(rows) - 1, len(rows) + 1):
                    for sensitive in (False, True):
                        with self.subTest(
                            section=section,
                            options=options,
                            offset=offset,
                            sensitive=sensitive,
                        ):
                            arguments = {
                                **options,
                                "offset": max(0, offset),
                                "limit": 3,
                                "include_sensitive": sensitive,
                            }
                            self.assertEqual(
                                query(report, section, **arguments),
                                query(legacy, section, **arguments),
                            )

    def test_small_queries_and_views_decode_only_needed_facts(self):
        _, report = self.fixture(record_count=30)
        cases = (
            (lambda: query(report, "endpoints", limit=1), 1),
            (
                lambda: query(report, "endpoints", identity="endpoint-2-0-29", limit=1),
                1,
            ),
            (
                lambda: query(
                    report, "evidence", identity="signal-evidence-2-0-29", limit=1
                ),
                1,
            ),
            (lambda: query(report, "evidence", offset=1, limit=2), 1),
            (lambda: query(report, "apps", limit=1), 0),
            (lambda: summary(report), 0),
        )
        for operation, expected in cases:
            with self.subTest(expected=expected, operation=operation):
                _, decoded = self.decoded(operation)
                self.assertEqual(len(decoded), expected)
        _, decoded = self.decoded(lambda: markdown(report, limit=1))
        self.assertLessEqual(len(decoded), 15)

    def test_findings_use_business_ids_without_decoding_for_id_projection(self):
        store, report = self.fixture()
        app = report["apps"][0]
        identities = list(store.finding_ids(app["id"]))
        finding = app["findings"][0]
        self.assertIn(finding["id"], identities)
        result, decoded = self.decoded(
            lambda: query(report, "findings", identity=finding["id"])
        )
        self.assertEqual(len(decoded), 1)
        self.assertEqual(result["items"][0]["id"], finding["id"])
        _, decoded = self.decoded(lambda: list(FindingIds(app["findings"])))
        self.assertEqual(decoded, [])

    def test_shared_ids_keep_application_scope_and_first_evidence_order(self):
        from benchmarks import performance

        original = performance.synthetic_result

        def shared(*args):
            result = original(*args)
            result["endpoints"][0]["id"] = "shared-endpoint"
            result["endpoints"][0]["evidence"][0]["id"] = "shared-evidence"
            result["signals"][0]["evidence"][0]["id"] = "shared-evidence"
            return result

        with patch.object(performance, "synthetic_result", side_effect=shared):
            _, report = self.fixture()
        legacy = self.native_report(report)
        for section, identity in (
            ("endpoints", "shared-endpoint"),
            ("evidence", "shared-evidence"),
        ):
            result = query(report, section, identity=identity, offset=1, limit=1)
            self.assertEqual(result["total"], 3)
            self.assertEqual(result["items"][0]["package"], "com.example.app1")
            self.assertEqual(
                result, query(legacy, section, identity=identity, offset=1, limit=1)
            )
        evidence = query(report, "evidence", identity="shared-evidence")["items"]
        self.assertTrue(all(item["kind"] == "dex_string" for item in evidence))

    def legacy_database(self, store):
        path = self.root / "legacy.sqlite3"
        connection = sqlite3.connect(path)
        store.connection.backup(connection)
        connection.execute("DROP TABLE evidence_refs")
        connection.execute("DELETE FROM metadata WHERE key LIKE 'app_view:%'")
        connection.execute("UPDATE metadata SET payload='1' WHERE key='store_version'")
        connection.execute(
            "UPDATE records SET identity=CAST(ordinal AS TEXT) WHERE scope='app' AND section='findings'"
        )
        connection.commit()
        connection.close()
        return path

    def test_v1_readonly_queries_exports_and_resume_preserve_original(self):
        store, report = self.fixture()
        expected = self.native_report(report)
        path = self.legacy_database(store)
        before = path.read_bytes()
        legacy = AnalysisStore(path, readonly=True)
        try:
            self.assertEqual(legacy.version, 1)
            loaded = legacy.report()
            self.assertEqual(summary(loaded), summary(expected))
            self.assertEqual(markdown(loaded, limit=2), markdown(expected, limit=2))
            for section in SECTIONS:
                for identity in (
                    None,
                    next(
                        (
                            row["id"]
                            for row in section_rows(expected, section)
                            if row.get("id")
                        ),
                        "absent",
                    ),
                ):
                    self.assertEqual(
                        query(loaded, section, identity=identity, offset=1, limit=3),
                        query(expected, section, identity=identity, offset=1, limit=3),
                    )
            target = self.store("resumed.sqlite3")
            with patch(
                "scripts.static_analysis.engine.analyze_artifact",
                side_effect=AssertionError("Unexpected reparse"),
            ):
                results = analyze_many(
                    report["artifacts"],
                    self.limits,
                    "standard",
                    self.cancel,
                    1,
                    None,
                    lambda event: None,
                    store=target,
                    resume_store=legacy,
                )
            self.assertEqual(len(results), len(report["artifacts"]))
            self.assertEqual(target.version, 2)
        finally:
            legacy.close()
        self.assertEqual(path.read_bytes(), before)
        with self.assertRaisesRegex(AnalysisError, "read-only"):
            AnalysisStore(path)
        self.assertEqual(path.read_bytes(), before)

    def test_projection_failure_rolls_back_application_and_all_derived_data(self):
        store, report = self.fixture()
        app = self.native_report(report)["apps"][0]
        endpoints = app["endpoints"]
        app["id"] = "interrupted"
        store.begin_app(app)
        store.merge(app["id"], "endpoints", endpoints, self.limits)
        with (
            patch.object(
                store,
                "_insert_evidence_refs",
                side_effect=Cancelled("Projection interrupted"),
            ),
            self.assertRaises(Cancelled),
        ):
            store.save_app(app)
        self.assertEqual(
            store.connection.execute("SELECT COUNT(*) FROM apps").fetchone()[0], 3
        )
        self.assertEqual(
            store.connection.execute(
                "SELECT COUNT(*) FROM records WHERE owner='interrupted'"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(store.evidence_count("interrupted"), 0)
        self.assertIsNone(store.metadata("app_view:interrupted"))

    def test_query_plans_use_record_and_evidence_identity_indexes(self):
        store, report = self.fixture()
        app_id = report["apps"][0]["id"]
        statements = (
            (
                "SELECT payload FROM records WHERE scope='app' AND owner=? AND section='endpoints' AND identity=?",
                (app_id, "endpoint-0-0-0"),
            ),
            (
                "SELECT section,parent,position FROM evidence_refs WHERE app_id=? AND identity=?",
                (app_id, "endpoint-evidence-0-0-0-0"),
            ),
        )
        for statement, parameters in statements:
            plan = " ".join(
                row[3]
                for row in store.connection.execute(
                    "EXPLAIN QUERY PLAN " + statement, parameters
                )
            )
            self.assertIn("SEARCH", plan)
            self.assertNotIn("SCAN ", plan)

    def test_record_encoding_preserves_bytes_failure_and_cancellation(self):
        records = [
            {
                "text": "\U0001f600",
                "values": [True, None, 3.5],
                "url": "https://example.org/?token=secret",
            }
        ]
        expected = "".join(json_chunks(records)) + "\n"
        path = self.root / "records.json"
        atomic_json(path, JsonRecords(records))
        self.assertEqual(path.read_text(), expected)
        for values in (records + [{"value": float("nan")}],):
            with self.assertRaises(ValueError):
                atomic_json(path, JsonRecords(values))
            self.assertEqual(path.read_text(), expected)

        class InterruptedRecords(JsonRecords):
            def __iter__(self):
                yield self.values[0]
                self_cancel.set()
                yield self.values[0]

        self_cancel = threading.Event()
        with self.assertRaises(Cancelled):
            atomic_json(path, InterruptedRecords(records), self_cancel)
        self.assertEqual(path.read_text(), expected)

    def test_long_text_checks_budget_inside_extraction(self):
        budget = unittest.mock.Mock()
        budget.check.side_effect = [
            None,
            None,
            None,
            MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE),
        ]
        collector = EndpointCollector(self.limits, budget)
        with self.assertRaises(MemoryBudgetExceeded):
            collector.add_text(
                " ".join(f"host{index}.example.org" for index in range(1000)),
                {"entry": "domains.txt"},
            )
        self.assertLess(len(collector.results()), 1000)

    def test_sdk_domain_matches_are_shared_across_dex_files(self):
        from scripts.static_analysis import engine, rules

        artifact = snapshot_file(
            make_apk(
                self.root / "multidex.apk",
                entries={"classes.dex": make_dex(), "classes2.dex": make_dex()},
            ),
            self.root / "artifacts",
            self.limits,
            self.cancel,
        )
        with patch.object(
            engine, "sdk_domain_matches", wraps=rules.sdk_domain_matches
        ) as matcher:
            result = analyze_artifact(artifact, self.limits, "standard", self.cancel)
        self.assertEqual(matcher.call_count, 1)
        self.assertFalse(result.get("resource_limited", False))
        for matched in rules.sdk_domain_matches(result["endpoints"]).values():
            self.assertLessEqual(len(matched), 3)

    def test_unicode_contains_preserves_casefold_semantics(self):
        store, report = self.fixture()
        app = report["apps"][0]
        endpoint = app["endpoints"][0]
        endpoint["value"] = "https://example.org/Stra\u00dfe/\u4e2d\u6587"
        endpoint["evidence"][0]["excerpt"] = endpoint["value"]
        store.update_record(app["id"], "endpoints", endpoint)
        store.connection.commit()
        legacy = self.native_report(report)
        for section in ("endpoints", "evidence"):
            for contains in ("STRASSE", "\u4e2d\u6587"):
                with self.subTest(section=section, contains=contains):
                    result = query(report, section, contains=contains)
                    self.assertGreater(result["total"], 0)
                    self.assertEqual(result, query(legacy, section, contains=contains))

    def test_sustained_dex_memory_stop_preserves_pending_checkpoints_for_resume(self):
        artifact = self.artifact()
        artifacts = [{**artifact, "sha256": f"{index:064x}"} for index in range(3)]
        source = self.store("stopped.sqlite3")
        with patch(
            "scripts.static_analysis.engine.dex_index",
            side_effect=MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE),
        ):
            results = analyze_many(
                artifacts,
                self.limits,
                "standard",
                self.cancel,
                1,
                None,
                lambda event: None,
                store=source,
            )
        self.assertTrue(results[artifacts[0]["sha256"]]["resource_limited"])
        self.assertTrue(
            all(
                any(
                    item["status"] == "CANCELLED"
                    for item in results[item["sha256"]]["stages"]
                )
                for item in artifacts[1:]
            )
        )
        destination = self.store("recovered.sqlite3")
        with patch(
            "scripts.static_analysis.engine.analyze_artifact", wraps=analyze_artifact
        ) as parser:
            recovered = analyze_many(
                artifacts,
                self.limits,
                "standard",
                threading.Event(),
                1,
                None,
                lambda event: None,
                store=destination,
                resume_store=source,
            )
        self.assertEqual(parser.call_count, 3)
        self.assertTrue(
            all(not value.get("resource_limited") for value in recovered.values())
        )

    def test_cache_cancellation_preserves_facts_and_marks_cancelled(self):
        artifact = self.artifact()
        with patch(
            "scripts.static_analysis.engine.cache_write",
            side_effect=Cancelled("Cache interrupted"),
        ):
            result = analyze_artifact(
                artifact, self.limits, "standard", self.cancel, self.root / "cache"
            )
        self.assertTrue(result["endpoints"])
        self.assertTrue(
            any(
                item["stage"] == "result_cache" and item["status"] == "CANCELLED"
                for item in result["stages"]
            )
        )

    def test_endpoint_optimization_matches_original_evidence_and_truncation(self):
        cases = (
            "alpha.example.org https://one.example.org/path //two.example.org/a",
            "https://one.example.org/path/inside.example.org?next=other.example.org",
            "https://bad_host.example.org/path https://valid.example.org:99999/path outside.example.org",
            "https://\u0062\u00fccher.example/path https://example.org/a(b)).",
            r"https:\/\/escaped.example.org\/events",
            "https%3A%2F%2Fencoded.example.org%2Fevents",
            "https://${host}/events sample.example.org com.example.App",
            "aHR0cHM6Ly9iYXNlNjQuZXhhbXBsZS5vcmcvY29sbGVjdA==",
            "//same.example.org/a same.example.org https://same.example.org/a",
        )
        outputs = []
        for limits in (Limits(), Limits(max_results=2, max_evidence=1)):
            collector = EndpointCollector(limits)
            for index, text in enumerate(cases):
                collector.add_text(
                    text,
                    {
                        "artifact": "fixture",
                        "entry": "assets/config.json",
                        "kind": "asset_strings",
                        "line": index,
                    },
                    [{"method": "Lexample/Test;->run()V", "instruction_offset": 2}]
                    if index % 2
                    else None,
                )
            outputs.append(
                {
                    "records": collector.results(),
                    "truncated": collector.truncated,
                    "evidence_truncated": collector.evidence_truncated,
                }
            )
        digest = hashlib.sha256(
            json.dumps(outputs, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(
            digest, "1b01208ce40689f9ffd492a71d743e7f0c02a57a8a8981cb088ef2463f53dc34"
        )

    def test_sdk_optimization_matches_original_rule_evidence(self):
        types = [
            "L" + prefixes[0] + "Example;"
            for _, _, prefixes, _ in SDK_RULES
            if prefixes
        ]
        endpoints = [
            {
                "id": f"endpoint-{index}",
                "host": domains[0],
                "evidence": [
                    {
                        "id": f"evidence-{index}",
                        "kind": "dex_string",
                        "entry": "classes.dex",
                    }
                ],
            }
            for index, (_, _, _, domains) in enumerate(SDK_RULES)
            if domains
        ]
        endpoints = endpoints * 5
        outputs = sdk_matches(types, endpoints, "fixture", "classes.dex")
        digest = hashlib.sha256(
            json.dumps(outputs, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(
            digest, "6b9b00c41bd578edf436544d683b51be7e0ec4cfc2fc89c03dcbaa52b7ea91d7"
        )


if __name__ == "__main__":
    unittest.main()
