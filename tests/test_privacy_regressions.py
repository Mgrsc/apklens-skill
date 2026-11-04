import copy
import hashlib
import json
import struct
import tempfile
import threading
import unittest
import zlib
from collections import Counter
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from privacy_fixtures import IDENTITY, ROOT_METHOD, privacy_dex, transmission
from support import make_apk

from scripts.static_analysis import dataflow, engine, storage
from scripts.static_analysis.binary import BinaryReader, dex_index
from scripts.static_analysis.common import (
    Budget,
    BudgetExceeded,
    Cancelled,
    Limits,
    MemoryBudgetExceeded,
    json_chunks,
    snapshot_file,
)
from scripts.static_analysis.reports import query, section_rows
from scripts.static_analysis.rules import signal_matches
from scripts.static_analysis.storage import AnalysisStore, ArtifactResults


def method_records(index):
    return [
        {"id": str(number), "artifact": "artifact", "entry": "classes.dex", **body}
        for number, body in enumerate(index["bodies"])
    ]


def checksummed(data):
    data = bytearray(data)
    struct.pack_into("<I", data, 32, len(data))
    struct.pack_into(
        "<I", data, 104, len(data) - struct.unpack_from("<I", data, 108)[0]
    )
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


class PrivacyRegressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()

    def parse(self, data, limits=None):
        limits = limits or self.limits
        return dex_index(data, limits, Budget(limits, self.cancel))

    def flows(self, data, limits=None):
        return dataflow.analyze_dataflow(
            method_records(self.parse(data, limits)), limits or self.limits, self.cancel
        )

    def source(self, register=0):
        return [("invoke", IDENTITY, [7], False), ("result", register)]

    def comparison(self, opcode, destination=6):
        constant = 0x13 if opcode <= 46 else 0x16
        return [
            0x0200 | constant,
            0,
            0x0400 | constant,
            0,
            destination << 8 | opcode,
            0x0402,
        ]

    def artifact(self, name, entries):
        return snapshot_file(
            make_apk(self.root / name, entries=entries),
            self.root / "artifacts",
            self.limits,
            self.cancel,
        )

    def store(self, name="analysis.sqlite3"):
        store = AnalysisStore(self.root / name, cancel=self.cancel)
        self.addCleanup(store.close)
        return store

    def paged_methods(self, methods):
        store = self.store()
        store.merge("app", "methods", methods, self.limits)
        return store.records("app", "app", "methods")

    def test_comparisons_preserve_method_and_call_paths(self):
        helper = "Lsample/Send;->send(Ljava/lang/String;)V"
        for opcode in range(45, 50):
            for cross_method in (False, True):
                with self.subTest(opcode=opcode, cross_method=cross_method):
                    definitions = [
                        {
                            "signature": ROOT_METHOD,
                            "code": [
                                *self.source(),
                                *self.comparison(opcode),
                                *transmission(),
                                0x0E,
                            ],
                        }
                    ]
                    if cross_method:
                        definitions = [
                            {
                                "signature": ROOT_METHOD,
                                "code": [
                                    *self.source(),
                                    ("invoke", helper, [0], True),
                                    0x0E,
                                ],
                            },
                            {
                                "signature": helper,
                                "code": [
                                    *self.comparison(opcode),
                                    *transmission(7),
                                    0x0E,
                                ],
                            },
                        ]
                    data = privacy_dex(definitions)
                    self.assertEqual(self.parse(data)["gaps"], [])
                    flows, coverage = self.flows(data)
                    self.assertEqual(len(flows), 1)
                    self.assertEqual(
                        flows[0]["evidence_level"], "E4" if cross_method else "E3"
                    )
                    self.assertTrue(
                        all(item["status"] == "COMPLETE" for item in coverage)
                    )

    def test_comparison_result_overwrites_previous_source(self):
        for opcode in range(45, 50):
            with self.subTest(opcode=opcode):
                data = privacy_dex(
                    [
                        {
                            "signature": ROOT_METHOD,
                            "code": [
                                *self.source(6),
                                *self.comparison(opcode),
                                (
                                    "invoke",
                                    "Ljava/lang/String;->valueOf(I)Ljava/lang/String;",
                                    [6],
                                    True,
                                ),
                                ("result", 0),
                                *transmission(),
                                0x0E,
                            ],
                        }
                    ]
                )
                flows, coverage = self.flows(data)
                self.assertEqual(flows, [])
                self.assertTrue(all(item["status"] == "COMPLETE" for item in coverage))

    def test_comparison_result_keeps_numeric_provenance(self):
        data = privacy_dex(
            [
                {
                    "signature": ROOT_METHOD,
                    "code": [
                        0x0112,
                        (
                            "invoke",
                            "Landroid/net/TrafficStats;->getUidRxBytes(I)J",
                            [1],
                            True,
                        ),
                        ("result", 2),
                        0x0416,
                        0,
                        0x0031,
                        0x0402,
                        (
                            "invoke",
                            "Ljava/lang/String;->valueOf(I)Ljava/lang/String;",
                            [0],
                            True,
                        ),
                        ("result", 0),
                        *transmission(),
                        0x0E,
                    ],
                }
            ]
        )
        flows, _ = self.flows(data)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["data_category"], "network_stats")
        self.assertTrue(any(item["excerpt"] == "49" for item in flows[0]["evidence"]))

    def test_unknown_comparison_result_does_not_reuse_constants(self):
        for opcode in range(45, 50):
            with self.subTest(opcode=opcode):
                data = privacy_dex(
                    [
                        {
                            "signature": ROOT_METHOD,
                            "code": [
                                *self.source(),
                                0x1612,
                                *self.comparison(opcode),
                                0x0638,
                                3,
                                0x0E,
                                *transmission(),
                                0x0E,
                            ],
                        }
                    ]
                )
                flows, _ = self.flows(data)
                self.assertEqual(len(flows), 1)
                self.assertTrue(flows[0]["conditions"])

    def test_comparisons_do_not_invent_exception_edges(self):
        for opcode in range(45, 50):
            with self.subTest(opcode=opcode):
                data = privacy_dex(
                    [
                        {
                            "signature": ROOT_METHOD,
                            "code": [
                                *self.comparison(opcode),
                                0x0E,
                                0x000D,
                                *self.source(),
                                *transmission(),
                                0x0E,
                            ],
                            "handlers": [(4, 6, 7)],
                        }
                    ]
                )
                flows, coverage = self.flows(data)
                self.assertEqual(flows, [])
                self.assertTrue(all(item["status"] == "COMPLETE" for item in coverage))

    def test_wide_comparison_requires_both_register_words(self):
        data = privacy_dex(
            [
                {
                    "signature": ROOT_METHOD,
                    "code": [
                        *self.source(),
                        0x0416,
                        0,
                        0x0631,
                        0x0407,
                        *transmission(),
                        0x0E,
                    ],
                }
            ]
        )
        flows, coverage = self.flows(data)
        self.assertEqual(flows, [])
        gaps = coverage[0]["metrics"]["gaps"]
        self.assertTrue(any("register" in item["reason"].lower() for item in gaps))

    def test_newer_unmodeled_instructions_remain_located_boundaries(self):
        for opcode, width in (
            (250, 4),
            (251, 4),
            (252, 3),
            (253, 3),
            (254, 2),
            (255, 2),
        ):
            with self.subTest(opcode=opcode):
                data = privacy_dex(
                    [
                        {
                            "signature": ROOT_METHOD,
                            "code": [
                                *self.source(),
                                opcode,
                                *([0] * (width - 1)),
                                *transmission(),
                                0x0E,
                            ],
                        }
                    ]
                )
                flows, coverage = self.flows(data)
                self.assertEqual(flows, [])
                self.assertTrue(
                    any(
                        item.get("excerpt") == str(opcode)
                        and item["reason"] == "unmodeled_instruction"
                        for item in coverage[0]["metrics"]["gaps"]
                    )
                )

    def test_plain_transforms_do_not_create_encoding_signals(self):
        for signature in (
            "Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;",
            "Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;",
            "Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;",
            "Ljava/lang/String;->getBytes()[B",
            "Ljava/lang/String;->getBytes(Ljava/lang/String;)[B",
            "Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B",
        ):
            with self.subTest(signature=signature):
                self.assertEqual(signal_matches(signature, {}, "E2"), [])
        for signature, category in (
            (
                "Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;",
                "data_encoding",
            ),
            ("Ljava/util/zip/GZIPOutputStream;->write([B)V", "data_encoding"),
            ("Ljavax/crypto/Cipher;->doFinal([B)[B", "cryptography"),
            ("Ljava/security/MessageDigest;->digest([B)[B", "cryptography"),
        ):
            with self.subTest(signature=signature):
                self.assertIn(
                    category,
                    {item["type"] for item in signal_matches(signature, {}, "E2")},
                )

    def test_boxing_does_not_exhaust_sensitive_signal_budget(self):
        box = {
            "signature": "Lsample/Box;->run()V",
            "code": [
                0x0012,
                *[
                    item
                    for _ in range(60)
                    for item in (
                        (
                            "invoke",
                            "Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;",
                            [0],
                            True,
                        ),
                        ("result", 1),
                    )
                ],
                0x0E,
            ],
        }
        sensitive = {
            "signature": ROOT_METHOD,
            "code": [*self.source(), *transmission(), 0x0E],
        }
        limits = replace(self.limits, max_results=40)
        for separate_dex in (False, True):
            with self.subTest(separate_dex=separate_dex):
                entries = {"classes.dex": privacy_dex([box, sensitive])}
                if separate_dex:
                    entries = {
                        "classes.dex": privacy_dex([box]),
                        "classes2.dex": privacy_dex([sensitive]),
                    }
                artifact = self.artifact(f"boxing-{separate_dex}.apk", entries)
                result = engine.analyze_artifact(
                    artifact, limits, "standard", self.cancel
                )
                self.assertTrue(
                    any(
                        item["type"] == "device_identifier"
                        and item["evidence_level"] == "E2"
                        for item in result["signals"]
                    )
                )
                self.assertTrue(
                    all(
                        item["status"] == "COMPLETE"
                        for item in result["stages"]
                        if item["stage"] == "signal_matching"
                    )
                )
                app = engine.build_apps(
                    [artifact], {artifact["sha256"]: result}, None, limits, "standard"
                )[0]
                self.assertTrue(
                    any(
                        item["type"] == "privacy_transmission_path"
                        for item in app["findings"]
                    )
                )

    def test_header_errors_do_not_poison_completed_method(self):
        first = {
            "signature": ROOT_METHOD,
            "code": [*self.source(), *transmission(), 0x0E],
        }
        for next_class in (False, True):
            with self.subTest(next_class=next_class):
                owner = "Lsample/Later;" if next_class else "Lsample/Main;"
                original = privacy_dex(
                    [first, {"signature": owner + "->later()V", "code": [0x0E]}]
                )
                before = self.parse(original)
                reader = BinaryReader(original)
                class_offset = reader.u32(100)
                position = reader.u32(class_offset + (32 if next_class else 0) + 24)
                if not next_class:
                    for _ in range(7):
                        _, position = reader.uleb(position)
                broken = bytearray(original)
                broken[position : position + 5] = b"\x80" * 5
                after = self.parse(checksummed(broken))
                self.assertTrue(after["gaps"])
                self.assertEqual(after["bodies"][0], before["bodies"][0])
                flows, _ = dataflow.analyze_dataflow(
                    method_records(after), self.limits, self.cancel
                )
                self.assertEqual(len(flows), 1)

    def test_unretained_body_error_does_not_poison_retained_method(self):
        original = privacy_dex(
            [
                {
                    "signature": ROOT_METHOD,
                    "code": [*self.source(), *transmission(), 0x0E],
                },
                {"signature": "Lsample/Main;->later()V", "code": [0x0E]},
            ]
        )
        before = self.parse(original)
        broken = bytearray(original)
        struct.pack_into("<H", broken, before["bodies"][1]["code_offset"] + 16, 0x18)
        after = self.parse(checksummed(broken), replace(self.limits, max_results=1))
        self.assertTrue(after["gaps"])
        self.assertEqual(after["bodies"], [before["bodies"][0]])

    def test_current_body_errors_are_still_attributed(self):
        original = privacy_dex([{"signature": ROOT_METHOD, "code": [0x0E]}])
        before = self.parse(original)
        broken = bytearray(original)
        struct.pack_into("<H", broken, before["bodies"][0]["code_offset"] + 16, 0x18)
        after = self.parse(checksummed(broken))
        self.assertTrue(after["gaps"])
        self.assertIn("gap", after["bodies"][0])
        flows, coverage = dataflow.analyze_dataflow(
            method_records(after), self.limits, self.cancel
        )
        self.assertEqual(flows, [])
        self.assertEqual(coverage[0]["status"], "PARTIAL")

    def test_hot_method_cache_reduces_decodes_without_changing_results(self):
        helper = "Lsample/Send;->send(Ljava/lang/String;)V"
        definitions = [
            {
                "signature": f"Lsample/App;->run{i}(Landroid/telephony/TelephonyManager;)V",
                "code": [
                    *self.source(),
                    ("invoke", helper, [0], True),
                    0x0E,
                ],
            }
            for i in range(20)
        ]
        definitions.append(
            {"signature": helper, "code": [*([0] * 128), *transmission(7), 0x0E]}
        )
        methods = method_records(self.parse(privacy_dex(definitions)))
        original_methods = copy.deepcopy(methods)
        expected = dataflow.analyze_dataflow(methods, self.limits, self.cancel)
        records = self.paged_methods(methods)
        decodes = Counter()
        original_loads = json.loads

        def decoded(payload):
            value = original_loads(payload)
            if isinstance(value, dict) and "instructions" in value:
                decodes[value["signature"]] += 1
            return value

        with patch.object(
            storage, "json", SimpleNamespace(loads=decoded, dumps=json.dumps)
        ):
            actual = dataflow.analyze_dataflow(records, self.limits, self.cancel)
        self.assertEqual(actual, expected)
        self.assertEqual(methods, original_methods)
        self.assertEqual(len(actual[0]), 20)
        self.assertLessEqual(decodes[helper], 2)

    def test_method_cache_eviction_and_oversized_entries_are_bounded(self):
        methods = method_records(
            self.parse(
                privacy_dex(
                    [
                        {"signature": f"Lsample/App;->run{i}()V", "code": [0x0E]}
                        for i in range(4)
                    ]
                )
            )
        )
        methods[-1]["instructions"][0]["value"] = "x" * 65536
        analyzer = dataflow.Analyzer(
            self.paged_methods(methods), self.limits, self.cancel
        )
        analyzer.index = {
            method["signature"]: [(i, method["id"])] for i, method in enumerate(methods)
        }
        original_page = analyzer.methods.page
        reads = Counter()

        def paged(*args, **kwargs):
            reads[kwargs.get("identity")] += 1
            return original_page(*args, **kwargs)

        sizes = []
        for method in methods[:3]:
            analyzer.cache_method(method["id"], method)
            sizes.append(analyzer.method_cache[method["id"]][1])
        byte_limit = sum(sorted(sizes)[-2:])
        analyzer.method_cache.clear()
        analyzer.method_cache_bytes = 0
        with (
            patch.object(dataflow, "MAX_METHOD_CACHE_ENTRIES", 2),
            patch.object(dataflow, "MAX_METHOD_CACHE_BYTES", byte_limit),
            patch.object(analyzer.methods, "page", side_effect=paged),
        ):
            for index in (0, 1, 0, 2, 1):
                self.assertEqual(
                    analyzer.lookup(methods[index]["signature"]), methods[index]
                )
                self.assertLessEqual(len(analyzer.method_cache), 2)
                self.assertLessEqual(analyzer.method_cache_bytes, byte_limit)
            self.assertEqual(reads[methods[0]["id"]], 1)
            self.assertEqual(reads[methods[1]["id"]], 2)
            cached = list(analyzer.method_cache)
            self.assertEqual(analyzer.lookup(methods[3]["signature"]), methods[3])
            self.assertEqual(list(analyzer.method_cache), cached)
            self.assertNotIn(methods[3]["id"], analyzer.method_cache)

    def test_method_cache_hits_still_enforce_resource_checks(self):
        methods = method_records(
            self.parse(
                privacy_dex([{"signature": "Lsample/App;->run()V", "code": [0x0E]}])
            )
        )
        analyzer = dataflow.Analyzer(
            self.paged_methods(methods), self.limits, self.cancel
        )
        analyzer.index = {methods[0]["signature"]: [(0, methods[0]["id"])]}
        analyzer.lookup(methods[0]["signature"])
        for error in (
            Cancelled("Stopped"),
            BudgetExceeded("Timed out"),
            MemoryBudgetExceeded("Memory limit"),
        ):
            with (
                self.subTest(error=type(error).__name__),
                patch.object(analyzer.budget, "check", side_effect=error),
                self.assertRaises(type(error)),
            ):
                analyzer.lookup(methods[0]["signature"])

    def test_method_cache_byte_budget_evicts_before_entry_limit(self):
        methods = method_records(
            self.parse(
                privacy_dex(
                    [
                        {"signature": f"Lsample/App;->run{i}()V", "code": [0x0E]}
                        for i in range(2)
                    ]
                )
            )
        )
        analyzer = dataflow.Analyzer(
            self.paged_methods(methods), self.limits, self.cancel
        )
        analyzer.index = {
            method["signature"]: [(i, method["id"])] for i, method in enumerate(methods)
        }
        analyzer.lookup(methods[0]["signature"])
        limit = analyzer.method_cache_bytes * 3 // 2
        with patch.object(dataflow, "MAX_METHOD_CACHE_BYTES", limit):
            analyzer.lookup(methods[1]["signature"])
        self.assertEqual(list(analyzer.method_cache), [methods[1]["id"]])
        self.assertLessEqual(analyzer.method_cache_bytes, limit)

    def test_json_evidence_does_not_visit_structure_facts(self):
        class UnreadableFacts:
            def __iter__(self):
                raise AssertionError("Structure facts must not be scanned for evidence")

        report = {
            "apps": [
                {
                    "id": "app",
                    "package": "sample.app",
                    "user": None,
                    "methods": UnreadableFacts(),
                    "fields": UnreadableFacts(),
                    "findings": [{"id": "finding", "evidence": [{"id": "evidence"}]}],
                }
            ]
        }
        self.assertEqual(
            [item["id"] for item in section_rows(report, "evidence")], ["evidence"]
        )

    def test_evidence_index_skips_structure_and_preserves_queries(self):
        data = privacy_dex(
            [
                {
                    "signature": ROOT_METHOD,
                    "code": [*self.source(), *transmission(), 0x0E],
                }
            ],
            fields=["Lsample/Main;->imei:Ljava/lang/String;"],
        )
        artifact = self.artifact("evidence.apk", {"classes.dex": data})
        store = self.store()
        store.save_artifact(
            artifact["sha256"],
            engine.analyze_artifact(artifact, self.limits, "standard", self.cancel),
        )
        saving = [False]
        visits = []
        original_page = storage.Records.page
        original_save = AnalysisStore.save_app

        def paged(records, *args, **kwargs):
            if saving[0] and records.section in {"methods", "fields"}:
                visits.append(records.section)
            return original_page(records, *args, **kwargs)

        def saved(instance, app):
            saving[0] = True
            try:
                return original_save(instance, app)
            finally:
                saving[0] = False

        with (
            patch.object(storage.Records, "page", paged),
            patch.object(AnalysisStore, "save_app", saved),
        ):
            apps = engine.build_apps(
                [artifact], ArtifactResults(store), None, self.limits, "standard", store
            )
        self.assertEqual(visits, [])
        report = {"apps": apps}
        native = json.loads("".join(json_chunks(report)))
        evidence = query(report, "evidence")
        self.assertEqual(evidence, query(native, "evidence"))
        for section in ("evidence", "methods", "fields", "findings"):
            expected = query(native, section)
            self.assertGreater(expected["total"], 0)
            for identity in (None, expected["items"][0]["id"], "missing"):
                for offset in (0, 1):
                    self.assertEqual(
                        query(
                            report, section, identity=identity, offset=offset, limit=1
                        ),
                        query(
                            native, section, identity=identity, offset=offset, limit=1
                        ),
                    )

    def test_previous_semantics_are_reparsed_on_cache_and_resume(self):
        data = privacy_dex(
            [
                {
                    "signature": ROOT_METHOD,
                    "code": [
                        *self.source(),
                        *self.comparison(49),
                        *transmission(),
                        0x0E,
                    ],
                }
            ]
        )
        artifact = self.artifact("resume.apk", {"classes.dex": data})
        cache = self.root / "cache"
        source = self.store("source.sqlite3")
        with (
            patch.object(engine, "ENGINE_VERSION", "1.1.0"),
            patch.object(engine, "RULE_VERSION", "2"),
            patch.object(engine, "MODEL_VERSION", "1"),
        ):
            old = engine.analyze_artifact(
                artifact, self.limits, "standard", self.cancel, cache
            )
            source.save_artifact(artifact["sha256"], old)
        before = (self.root / "source.sqlite3").read_bytes()
        target = self.store("target.sqlite3")
        with patch.object(engine, "dex_index", wraps=engine.dex_index) as parsed:
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
        self.assertEqual(parsed.call_count, 2)
        self.assertFalse(parsed.call_args_list[-1].kwargs["inspect_code"])
        key = engine.cache_key(artifact["sha256"], self.limits, "standard")
        self.assertNotEqual(old["cache_key"], key)
        self.assertEqual(results[artifact["sha256"]]["cache_key"], key)
        self.assertTrue(target.reusable(artifact["sha256"], key, False))
        self.assertEqual((self.root / "source.sqlite3").read_bytes(), before)
        app = engine.build_apps(
            [artifact], results, None, self.limits, "standard", target
        )[0]
        self.assertTrue(
            any(item["type"] == "privacy_transmission_path" for item in app["findings"])
        )
