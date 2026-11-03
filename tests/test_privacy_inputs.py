import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from privacy_fixtures import (
    IDENTITY,
    OPEN,
    ROOT_METHOD,
    URL_INIT,
    privacy_dex,
    transmission,
)
from support import make_apk

from scripts.static_analysis import dataflow, engine
from scripts.static_analysis.binary import dex_index
from scripts.static_analysis.common import (
    Budget,
    Cancelled,
    Limits,
    MemoryBudgetExceeded,
    json_chunks,
    snapshot_file,
)
from scripts.static_analysis.reports import query, summary
from scripts.static_analysis.rules import capabilities, signal_matches
from scripts.static_analysis.storage import AnalysisStore, ArtifactResults

CLI = Path(engine.__file__).resolve().parents[1] / "analyze.py"
INVALID_LITERALS = (
    "http://[",
    "http://exa\uff0fmple.com",
    "http://safe.example:70000/path",
    "http://safe.example:invalid/path",
    "http://safe.example:0/path",
    "http:///path",
    "relative/path",
    "",
    0,
    1,
)


def url_definition(literal, *, transmit=True, owner="Lsample/Main;"):
    constant = (
        ("string", 2, literal) if isinstance(literal, str) else literal << 12 | 0x0212
    )
    if not transmit:
        return {
            "signature": owner + "->run()V",
            "code": [
                ("new", 1, "Ljava/net/URL;"),
                constant,
                ("invoke", URL_INIT, [1, 2], False),
                ("invoke", OPEN, [1], False),
                ("result", 3),
                0x0E,
            ],
        }
    code = [("invoke", IDENTITY, [7], False), ("result", 0), *transmission(), 0x0E]
    return {
        "signature": owner + ROOT_METHOD.split(";", 1)[1],
        "code": [
            constant
            if isinstance(item, tuple) and item[0] == "string" and item[1] == 2
            else item
            for item in code
        ],
    }


def okhttp_definition(literal):
    return {
        "signature": ROOT_METHOD,
        "code": [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            ("new", 1, "Lokhttp3/Request$Builder;"),
            ("invoke", "Lokhttp3/Request$Builder;-><init>()V", [1], False),
            ("string", 2, literal)
            if isinstance(literal, str)
            else literal << 12 | 0x0212,
            (
                "invoke",
                "Lokhttp3/Request$Builder;->url(Ljava/lang/String;)Lokhttp3/Request$Builder;",
                [1, 2],
                False,
            ),
            ("result", 1),
            0x0312,
            (
                "invoke",
                "Lokhttp3/RequestBody;->create(Ljava/lang/String;Lokhttp3/MediaType;)Lokhttp3/RequestBody;",
                [0, 3],
                True,
            ),
            ("result", 3),
            (
                "invoke",
                "Lokhttp3/Request$Builder;->post(Lokhttp3/RequestBody;)Lokhttp3/Request$Builder;",
                [1, 3],
                False,
            ),
            ("result", 1),
            (
                "invoke",
                "Lokhttp3/Request$Builder;->build()Lokhttp3/Request;",
                [1],
                False,
            ),
            ("result", 3),
            ("new", 4, "Lokhttp3/OkHttpClient;"),
            (
                "invoke",
                "Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;",
                [4, 3],
                False,
            ),
            ("result", 5),
            ("invoke", "Lokhttp3/Call;->execute()Lokhttp3/Response;", [5], False),
            0x0E,
        ],
    }


class PrivacyInputTests(unittest.TestCase):
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

    def artifact(self, name, definitions, *, fields=()):
        path = make_apk(
            self.root / (name + ".apk"),
            package="com.example." + name,
            entries={"classes.dex": privacy_dex(definitions, fields=fields)},
        )
        return snapshot_file(path, self.root / "artifacts", self.limits, self.cancel)

    def store(self, name):
        store = AnalysisStore(self.root / name, cancel=self.cancel)
        self.addCleanup(store.close)
        return store

    def report(self, apps):
        return {
            "schema_version": 1,
            "engine_version": engine.ENGINE_VERSION,
            "run": {},
            "totals": {},
            "limitations": [],
            "apps": apps,
        }

    def test_invalid_url_does_not_block_later_root(self):
        for literal in INVALID_LITERALS:
            with self.subTest(literal=literal):
                methods = self.methods(
                    [
                        url_definition(literal),
                        url_definition("https://safe.example/path", owner="Lsample/Z;"),
                    ]
                )
                flows, coverage = dataflow.analyze_dataflow(methods, self.limits)
                self.assertEqual(len(flows), 1)
                self.assertTrue(
                    flows[0]["evidence"][0]["method"].startswith("Lsample/Z;")
                )
                self.assertEqual(coverage[0]["status"], "PARTIAL")
                gaps = coverage[0]["metrics"]["gaps"]
                self.assertTrue(
                    any("Endpoint literal" in item["reason"] for item in gaps)
                )
                self.assertTrue(all("instruction_offset" in item for item in gaps))

    def test_valid_urls_keep_original_literals_and_complete_paths(self):
        for literal in (
            "https://safe.example/path?value=one#fragment",
            "HTTP://Safe.Example:80/path",
            "http://[2001:db8::1]:8080/path",
            "ftp://safe.example/path",
            "ftps://safe.example/path",
        ):
            with self.subTest(literal=literal):
                methods = self.methods([url_definition(literal)])
                original = copy.deepcopy(methods)
                flows, coverage = dataflow.analyze_dataflow(methods, self.limits)
                self.assertEqual(len(flows), 1)
                self.assertEqual(flows[0]["sink"]["endpoints"], [literal])
                self.assertEqual(
                    flows[0]["sink"]["endpoint_status"], "resolved_candidate"
                )
                self.assertEqual(coverage[0]["status"], "COMPLETE")
                self.assertEqual(methods, original)

    def test_file_url_remains_a_known_non_network_path(self):
        flows, coverage = dataflow.analyze_dataflow(
            self.methods([url_definition("file:///private/cache")]), self.limits
        )
        self.assertEqual(flows, [])
        self.assertEqual(coverage[0]["status"], "COMPLETE")

    def test_unknown_url_remains_unresolved(self):
        definition = url_definition("https://safe.example")
        definition["signature"] = (
            "Lsample/Main;->run(Landroid/telephony/TelephonyManager;Ljava/lang/String;)V"
        )
        definition["code"][0] = ("invoke", IDENTITY, [6], False)
        definition["code"] = [
            0x7207
            if isinstance(item, tuple) and item[0] == "string" and item[1] == 2
            else item
            for item in definition["code"]
        ]
        flows, coverage = dataflow.analyze_dataflow(
            self.methods([definition]), self.limits
        )
        self.assertEqual(flows, [])
        self.assertEqual(coverage[0]["status"], "PARTIAL")
        self.assertIn("endpoint are unresolved", json.dumps(coverage))

    def test_unmodeled_url_protocol_is_a_located_gap(self):
        flows, coverage = dataflow.analyze_dataflow(
            self.methods([url_definition("custom:payload")]), self.limits
        )
        self.assertEqual(flows, [])
        self.assertEqual(coverage[0]["status"], "PARTIAL")
        self.assertIn("Endpoint literal", json.dumps(coverage))

    def test_okhttp_invalid_literals_are_not_resolved_destinations(self):
        for literal in INVALID_LITERALS:
            with self.subTest(literal=literal):
                flows, coverage = dataflow.analyze_dataflow(
                    self.methods([okhttp_definition(literal)]), self.limits
                )
                self.assertEqual(len(flows), 1)
                self.assertEqual(flows[0]["sink"]["endpoints"], [])
                self.assertEqual(flows[0]["sink"]["endpoint_status"], "unresolved")
                self.assertEqual(coverage[0]["status"], "PARTIAL")
                self.assertIn("Endpoint literal", json.dumps(coverage))

    def test_okhttp_valid_url_preserves_payload_and_endpoint(self):
        literal = "https://safe.example/path"
        flows, coverage = dataflow.analyze_dataflow(
            self.methods([okhttp_definition(literal)]), self.limits
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["data_category"], "device_identifier")
        self.assertEqual(flows[0]["sink"]["endpoints"], [literal])
        self.assertEqual(coverage[0]["status"], "COMPLETE")

    def test_okhttp_non_http_literals_do_not_become_resolved_candidates(self):
        for literal in (
            "ftp://safe.example/path",
            "file:///private/cache",
            "custom:payload",
        ):
            with self.subTest(literal=literal):
                flows, coverage = dataflow.analyze_dataflow(
                    self.methods([okhttp_definition(literal)]), self.limits
                )
                self.assertEqual(len(flows), 1)
                self.assertEqual(flows[0]["sink"]["endpoints"], [])
                self.assertEqual(flows[0]["sink"]["endpoint_status"], "unresolved")
                self.assertEqual(coverage[0]["status"], "PARTIAL")

    def test_emit_revalidates_mixed_alias_destinations_without_coercion(self):
        analyzer = dataflow.Analyzer([], self.limits)
        node = dataflow.Node(
            "artifact", "classes.dex", "Lsample/Main;->run()V", 0, "call", "source"
        )
        state = {"heap": {}, "files": {}, "statics": {}, "conditions": []}
        source = analyzer.source("device_identifier", node)
        analyzer.emit(
            source,
            node,
            state,
            (
                "https://safe.example/path",
                1,
                None,
                {},
                [],
                "http://[",
                "https://safe.example/path",
            ),
        )
        flows = list(analyzer.flows.values())
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["sink"]["endpoints"], ["https://safe.example/path"])
        self.assertTrue(analyzer.gaps)
        self.assertTrue(
            all("instruction_offset" in item for item in analyzer.gaps.values())
        )

    def test_url_input_handling_preserves_resource_exceptions(self):
        methods = self.methods([url_definition("https://safe.example/path")])
        for kind in (Cancelled, MemoryBudgetExceeded):
            with (
                self.subTest(kind=kind.__name__),
                patch.object(dataflow, "urlsplit", side_effect=kind("stop")),
                self.assertRaises(kind),
            ):
                dataflow.analyze_dataflow(methods, self.limits)

    def test_ordinary_version_fields_do_not_require_sensitive_review(self):
        for name, field_type in (
            ("versionName", "Ljava/lang/String;"),
            ("versionCode", "I"),
        ):
            with self.subTest(name=name):
                item = self.artifact(
                    name.lower(),
                    [{"signature": "Lsample/State;->run()V", "code": [0x0E]}],
                    fields=["Lsample/State;->" + name + ":" + field_type],
                )
                parsed = engine.analyze_artifact(
                    item, self.limits, "standard", self.cancel
                )
                apps = engine.build_apps(
                    [item], {item["sha256"]: parsed}, None, self.limits, "standard"
                )
                self.assertFalse(
                    any(
                        s["type"] == "application_fingerprint"
                        for s in apps[0]["signals"]
                    )
                )
                self.assertEqual(apps[0]["priority"]["reasons"], [])
                self.assertEqual(summary(self.report(apps))["review_required_total"], 0)
                self.assertEqual(len(apps[0]["fields"]), 1)

    def test_fingerprint_rule_keeps_framework_fields_and_precise_apis(self):
        for value in (
            "Landroid/content/pm/PackageInfo;->versionName:Ljava/lang/String;",
            "Landroid/content/pm/PackageInfo;->versionCode:I",
            "Landroid/content/pm/SigningInfo;",
            "GET_SIGNING_CERTIFICATES",
        ):
            with self.subTest(value=value):
                self.assertIn(
                    "application_fingerprint",
                    {s["type"] for s in signal_matches(value, {})},
                )
        for signature, category in dataflow.SOURCE_METHODS.items():
            if category != "application_fingerprint":
                continue
            with self.subTest(signature=signature):
                self.assertIn(
                    category, {s["type"] for s in signal_matches(signature, {}, "E2")}
                )
        for value in (
            "versionName",
            "versionCode",
            "versionName versionCode",
            "Lsample/State;->versionName:Ljava/lang/String;",
            "Landroid/content/pm/PackageInfo;->versionCode:Ljava/lang/String;",
        ):
            with self.subTest(value=value):
                self.assertNotIn(
                    "application_fingerprint",
                    {s["type"] for s in signal_matches(value, {})},
                )

    def test_capability_level_uses_strongest_signal_in_any_order(self):
        for levels in (("E1",), ("E2",), ("E1", "E2"), ("E2", "E1")):
            for category in ("device_identifier", "usage_stats", "sensor_api"):
                with self.subTest(levels=levels, category=category):
                    signals = [
                        {"type": category, "evidence_level": level} for level in levels
                    ]
                    result = capabilities(
                        [{"name": "android.permission.READ_PHONE_STATE"}], signals
                    )
                    self.assertEqual(
                        next(
                            item["evidence_level"]
                            for item in result
                            if item["type"] == category
                        ),
                        max(levels),
                    )
                    self.assertEqual(
                        next(
                            item["evidence_level"]
                            for item in result
                            if item["type"] == "device_identity"
                        ),
                        "E0",
                    )

    def scan(self, name, arguments):
        output = self.root / name
        result = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "scan",
                "--output",
                str(output),
                "--quiet",
                "--jobs",
                "1",
                "--memory-mib",
                "256",
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for filename in (
            "analysis.json",
            "summary.json",
            "report.md",
            "analysis.sqlite3",
        ):
            self.assertTrue((output / filename).is_file(), filename)
        self.assertEqual(
            json.loads((output / "progress.json").read_text())["event"], "completed"
        )
        return output

    def test_cli_bad_literal_does_not_stop_mixed_batch(self):
        good = self.artifact("aaa", [url_definition("https://safe.example/path")])
        bad = self.artifact("zzz", [url_definition("http://[")])
        for mode in ("standard", "quick", "decompile"):
            with self.subTest(mode=mode):
                output = self.scan(
                    mode,
                    [
                        "--apk",
                        good["path"],
                        "--apk",
                        bad["path"],
                        "--mode",
                        mode,
                        "--no-cache",
                    ],
                )
                report = json.loads((output / "analysis.json").read_text())
                self.assertEqual(len(report["apps"]), 2)
                flows = [
                    f
                    for app in report["apps"]
                    for f in app["findings"]
                    if f["type"] == "privacy_transmission_path"
                ]
                self.assertEqual(len(flows), 0 if mode == "quick" else 1)
                if mode != "quick":
                    self.assertIn(
                        "Endpoint literal", json.dumps(report["apps"][1]["coverage"])
                    )

    def test_cli_bad_literal_supports_cache_hits_and_new_directory_resume(self):
        item = self.artifact("cached", [url_definition("http://[")])
        cache = self.root / "cache"
        first = self.scan(
            "first",
            ["--apk", item["path"], "--mode", "standard", "--cache-dir", str(cache)],
        )
        second = self.scan(
            "second",
            ["--apk", item["path"], "--mode", "standard", "--cache-dir", str(cache)],
        )
        with closing(sqlite3.connect(second / "analysis.sqlite3")) as connection:
            payload = json.loads(
                connection.execute("SELECT payload FROM artifacts").fetchone()[0]
            )
        self.assertTrue(payload["cache"]["hit"])
        before = (first / "analysis.sqlite3").read_bytes()
        resumed = self.scan("resumed", ["--resume", str(first)])
        self.assertIn("Endpoint literal", (resumed / "analysis.json").read_text())
        self.assertEqual((first / "analysis.sqlite3").read_bytes(), before)

    def test_json_sqlite_and_memory_keep_evidence_capability_and_gap_queries(self):
        artifacts = [
            self.artifact("aaa", [url_definition("https://safe.example/path")]),
            self.artifact("zzz", [url_definition("http://[")]),
        ]
        results = {
            item["sha256"]: engine.analyze_artifact(
                item, self.limits, "standard", self.cancel
            )
            for item in artifacts
        }
        store = self.store("analysis.sqlite3")
        for identity, parsed in results.items():
            store.save_artifact(identity, parsed)
        apps = engine.build_apps(
            artifacts, ArtifactResults(store), None, self.limits, "standard", store
        )
        report = self.report(apps)
        native = json.loads("".join(json_chunks(report)))
        memory = self.report(
            engine.build_apps(artifacts, results, None, self.limits, "standard")
        )
        self.assertEqual(summary(report), summary(native))
        self.assertEqual(summary(report), summary(memory))
        for section in (
            "findings",
            "evidence",
            "capabilities",
            "signals",
            "methods",
            "coverage",
        ):
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
        for app in native["apps"]:
            self.assertEqual(
                next(
                    c["evidence_level"]
                    for c in app["capabilities"]
                    if c["type"] == "device_identifier"
                ),
                "E2",
            )

    def test_previous_input_semantics_invalidate_cache_and_resume(self):
        item = self.artifact("prior", [url_definition("http://[")])
        cache = self.root / "cache"
        source = self.store("source.sqlite3")
        with (
            patch.object(engine, "ENGINE_VERSION", "1.1.2"),
            patch.object(engine, "RULE_VERSION", "3"),
            patch.object(engine, "MODEL_VERSION", "3"),
        ):
            old = engine.analyze_artifact(
                item, self.limits, "standard", self.cancel, cache
            )
            source.save_artifact(item["sha256"], old)
        before = (self.root / "source.sqlite3").read_bytes()
        target = self.store("target.sqlite3")
        with patch.object(engine, "dex_index", wraps=engine.dex_index) as parse:
            results = engine.analyze_many(
                [item],
                self.limits,
                "standard",
                self.cancel,
                1,
                cache,
                lambda event: None,
                store=target,
                resume_store=source,
            )
        self.assertEqual(parse.call_count, 1)
        self.assertNotEqual(old["cache_key"], results[item["sha256"]]["cache_key"])
        self.assertEqual((self.root / "source.sqlite3").read_bytes(), before)
        apps = engine.build_apps([item], results, None, self.limits, "standard", target)
        self.assertIn(
            "Endpoint literal", json.dumps(query(self.report(apps), "coverage"))
        )
