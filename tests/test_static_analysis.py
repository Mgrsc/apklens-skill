import json
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from support import make_apk, make_axml, make_dex, make_pool

from scripts.static_analysis.binary import dex_index, resource_strings, xml_nodes
from scripts.static_analysis.common import (
    AnalysisError,
    Budget,
    Limits,
    run_command,
    snapshot_file,
)
from scripts.static_analysis.device import (
    DeviceCollector,
    parse_appops,
    parse_dumpsys,
    parse_inventory,
)
from scripts.static_analysis.endpoints import (
    EndpointCollector,
    normalize_endpoint,
    sanitized,
)
from scripts.static_analysis.engine import analyze_artifact, build_apps, source_view
from scripts.static_analysis.manifest import analyze_manifest
from scripts.static_analysis.reports import load_report, query

ROOT = Path(__file__).resolve().parents[1]


class BinaryTests(unittest.TestCase):
    def setUp(self):
        self.limits = Limits()

    def test_dex_direct_references_and_modified_utf8(self):
        index = dex_index(
            make_dex(["emoji-\U0001f600", "embedded\x00null"]),
            self.limits,
            Budget(self.limits),
        )
        self.assertEqual(
            index["references"][0][0]["method"], "Lcom/example/App;->run()V"
        )
        self.assertIn("->openConnection()", index["calls"][0]["target"])
        self.assertEqual(index["strings"][-2]["value"], "emoji-\U0001f600")
        self.assertEqual(index["strings"][-1]["value"], "embedded\x00null")
        self.assertEqual(index["gaps"], [])

    def test_axml_typed_values_and_namespace(self):
        facts = analyze_manifest(
            xml_nodes(make_axml(), self.limits, Budget(self.limits))
        )
        self.assertEqual(facts["package"], "com.example.binary")
        self.assertEqual(facts["version_code"], 7)
        self.assertFalse(facts["application"]["debuggable"])
        self.assertEqual(facts["application"]["network_security_config"], "@0x7f010001")
        self.assertEqual(facts["permissions"][0]["name"], "android.permission.CAMERA")
        self.assertFalse(facts["components"][0]["exported"])

    def test_resource_pools_support_utf8_and_utf16(self):
        values = ["https://resources.example.org/events", "value-\U0001f600", "a" * 160]
        for utf8 in (True, False):
            pool = make_pool(values, utf8)
            table = struct.pack("<HHII", 2, 12, 12 + len(pool), 0) + pool
            result = resource_strings(table, self.limits, Budget(self.limits))
            self.assertEqual([item["value"] for item in result], values)

    def test_malformed_binary_fails_explicitly(self):
        for data in (b"", b"dex\n035\x00" + b"\x00" * 104):
            with self.assertRaises(AnalysisError):
                dex_index(data, self.limits, Budget(self.limits))
        with self.assertRaises(AnalysisError):
            xml_nodes(make_axml()[:-1], self.limits, Budget(self.limits))

    def test_provider_default_and_inherited_permission(self):
        manifest = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><uses-sdk android:targetSdkVersion="16"/><application android:permission="com.example.LOCK"><provider android:name=".Provider"/><service android:name=".Service"><intent-filter/></service></application></manifest>'
        facts = analyze_manifest(xml_nodes(manifest, self.limits, Budget(self.limits)))
        self.assertTrue(facts["components"][0]["exported"])
        self.assertEqual(facts["components"][1]["permission"], "com.example.LOCK")

    def test_unresolved_target_sdk_keeps_exported_unknown(self):
        manifest = '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><uses-sdk android:targetSdkVersion="@integer/target"/><application><provider android:name=".Provider"/></application></manifest>'
        facts = analyze_manifest(
            xml_nodes(manifest.encode("utf-16"), self.limits, Budget(self.limits))
        )
        self.assertIsNone(facts["components"][0]["exported"])

    def test_dex_checksum_failure_is_detected(self):
        data = bytearray(make_dex())
        data[-1] ^= 1
        with self.assertRaisesRegex(AnalysisError, "checksum"):
            dex_index(bytes(data), self.limits, Budget(self.limits))


class EndpointTests(unittest.TestCase):
    def test_normalization_keeps_path_case_and_query_order(self):
        value = normalize_endpoint(
            "HTTPS://User:Password@EXAMPLE.org:443/Case?a=1&b=2#fragment"
        )
        self.assertEqual(value["value"], "https://example.org/Case?a=1&b=2")
        self.assertTrue(value["has_userinfo"])
        self.assertEqual(
            normalize_endpoint("http://[2001:db8::1]:8080/log")["host"], "2001:db8::1"
        )
        self.assertIsNone(normalize_endpoint("https://example.org:99999/"))

    def test_escaped_base64_unicode_and_multiple_urls(self):
        collector = EndpointCollector(Limits())
        source = {
            "artifact": "hash",
            "entry": "assets/test.json",
            "kind": "asset_strings",
        }
        collector.add_text(
            r"https:\/\/escaped.example.org\/track https://plain.example.org/a", source
        )
        collector.add_text("aHR0cHM6Ly9iYXNlNjQuZXhhbXBsZS5vcmcvY29sbGVjdA==", source)
        collector.add_text("https://b\u00fccher.example/path", source)
        values = collector.results()
        self.assertTrue(any(item["host"] == "escaped.example.org" for item in values))
        self.assertTrue(any(item["host"] == "base64.example.org" for item in values))
        self.assertTrue(any(item["host"] == "xn--bcher-kva.example" for item in values))

    def test_evidence_upgrades_only_for_direct_references(self):
        collector = EndpointCollector(Limits())
        collector.add_text(
            "https://events.example.org/collect",
            {"artifact": "a", "entry": "classes.dex", "kind": "dex_string"},
            [{"method": "LExample;->run()V", "instruction_offset": 0}],
        )
        endpoint = collector.results()[0]
        self.assertEqual(endpoint["evidence_level"], "E2")
        self.assertEqual(endpoint["tags"], ["telemetry_path_candidate"])
        self.assertNotIn("dataflow", endpoint)

    def test_template_and_bare_domains_are_distinct(self):
        collector = EndpointCollector(Limits())
        collector.add_text(
            "https://${host}/events sample.example.org com.example.App",
            {"entry": "assets/config", "kind": "asset_strings"},
        )
        self.assertTrue(
            any(item["kind"] == "unresolved_template" for item in collector.results())
        )
        self.assertTrue(any(item["kind"] == "domain" for item in collector.results()))

    def test_redaction_and_budget_are_explicit(self):
        value = sanitized(
            {"excerpt": "https://name:secret@example.org/log?token=private#more"}
        )
        self.assertNotIn("private", value["excerpt"])
        self.assertNotIn("secret", value["excerpt"])
        collector = EndpointCollector(Limits(max_results=1))
        collector.add_text(
            "https://one.example.org/a https://two.example.org/b", {"entry": "x"}
        )
        self.assertTrue(collector.truncated)
        self.assertEqual(len(collector.results()), 1)


class DeviceTests(unittest.TestCase):
    def test_inventory_includes_apps_without_sensitive_permissions(self):
        packages, rejected = parse_inventory(
            "package:/data/app/a/base.apk=com.example.app installer=com.store uid:10200\npackage:/system/app/b.apk=android uid:1000\n"
        )
        self.assertEqual(set(packages), {"com.example.app", "android"})
        self.assertEqual(packages["com.example.app"]["uid"], "10200")
        self.assertFalse(rejected)

    def test_runtime_and_shared_uid_permissions_are_user_scoped(self):
        dump_lines = [
            "  Package [com.example.app] (a):",
            "    appId=1000",
            "    sharedUser=SharedUserSetting{ab android.uid.system/1000}",
            "    flags=[ SYSTEM ]",
            "    User 0:",
            "      runtime permissions:",
            "        android.permission.CAMERA: granted=false, flags=[]",
            "    User 10:",
            "      runtime permissions:",
            "        android.permission.CAMERA: granted=true, flags=[]",
            "  Package [com.example.other] (b):",
            "    appId=10200",
            "Shared users:",
            "  SharedUser [android.uid.system] (ab):",
            "    Packages",
            "      PackageSetting{ab com.example.app/1000}",
            "    install permissions:",
            "      android.permission.INTERNET: granted=true",
            "    User 0:",
            "      runtime permissions:",
            "        android.permission.READ_SMS: granted=true",
            "    User 10:",
            "      runtime permissions:",
            "        android.permission.READ_SMS: granted=false",
        ]
        dump = "\n".join(dump_lines)
        values = parse_dumpsys(dump, 0)
        self.assertFalse(
            values["com.example.app"]["permissions"]["android.permission.CAMERA"][
                "granted"
            ]
        )
        self.assertTrue(
            values["com.example.app"]["permissions"]["android.permission.READ_SMS"][
                "granted"
            ]
        )
        self.assertNotIn(
            "android.permission.INTERNET", values["com.example.other"]["permissions"]
        )

    def test_appops_default_is_not_converted_to_granted(self):
        self.assertEqual(
            parse_appops("GET_USAGE_STATS: default; time=never\nCAMERA: foreground"),
            {"GET_USAGE_STATS": "default", "CAMERA": "foreground"},
        )

    def test_collector_reads_all_splits_without_modifying_device(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = make_apk(root / "input.apk")
            calls = []

            def shell(arguments):
                calls.append(arguments)
                if arguments[:3] == ["pm", "list", "packages"]:
                    output = "package:/data/app/base.apk=com.example.app uid:10123\n"
                elif arguments[:2] == ["dumpsys", "package"]:
                    output = "  Package [com.example.app] (a):\n    appId=10123\n    install permissions:\n      android.permission.INTERNET: granted=true\n"
                elif arguments[:2] == ["pm", "path"]:
                    output = "package:/data/app/base.apk\npackage:/data/app/split_config.apk\n"
                else:
                    output = "null\n"
                return {"status": "COMPLETE", "reason": None, "stdout": output}

            def command(arguments, **kwargs):
                Path(arguments[-1]).write_bytes(fixture.read_bytes())
                return {"status": "COMPLETE", "reason": None}

            collector = DeviceCollector(
                "adb",
                "test-serial",
                0,
                root / "run" / "device",
                Limits(),
                threading.Event(),
            )
            with (
                patch.object(collector, "shell", side_effect=shell),
                patch(
                    "scripts.static_analysis.device.run_command", side_effect=command
                ),
            ):
                result = collector.collect([])
            self.assertEqual(len(result["artifacts"]), 2)
            self.assertEqual(
                len(result["packages"]["com.example.app"]["remote_paths"]), 2
            )
            self.assertFalse(
                any(
                    "set" in arguments or "uninstall" in arguments
                    for arguments in calls
                )
            )


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cancel = threading.Event()
        self.limits = Limits()

    def tearDown(self):
        self.temporary.cleanup()

    def artifact(self, path):
        return snapshot_file(path, self.root / "artifacts", self.limits, self.cancel)

    def test_multidex_resources_assets_and_native_strings(self):
        pool = make_pool(["https://resources.example.org/events"])
        table = struct.pack("<HHII", 2, 12, len(pool) + 12, 0) + pool
        apk = make_apk(
            self.root / "input.apk",
            entries={
                "classes.dex": make_dex(),
                "classes27.dex": make_dex(url="https://split.example.org/events"),
                "resources.arsc": table,
                "assets/settings.json": b'{"url":"https://assets.example.org/upload"}',
                "lib/arm64-v8a/libtest.so": b"\x00https://native.example.org/collect\x00",
            },
        )
        result = analyze_artifact(
            self.artifact(apk), self.limits, "standard", self.cancel
        )
        hosts = {item["host"] for item in result["endpoints"]}
        self.assertTrue(
            {
                "events.example.org",
                "split.example.org",
                "resources.example.org",
                "assets.example.org",
                "native.example.org",
            }
            <= hosts
        )
        self.assertEqual(result["statistics"]["dex_files"], 2)
        self.assertTrue(
            any(item["name"] == "Firebase Analytics" for item in result["sdks"])
        )

    def test_cache_reuse_and_corruption_recovery(self):
        artifact = self.artifact(
            make_apk(self.root / "input.apk", entries={"classes.dex": make_dex()})
        )
        cache = self.root / "cache"
        first = analyze_artifact(artifact, self.limits, "standard", self.cancel, cache)
        second = analyze_artifact(artifact, self.limits, "standard", self.cancel, cache)
        self.assertFalse(first["cache"]["hit"])
        self.assertTrue(second["cache"]["hit"])
        next(cache.glob("*.json")).write_text("broken", encoding="utf-8")
        third = analyze_artifact(artifact, self.limits, "standard", self.cancel, cache)
        self.assertFalse(third["cache"]["hit"])
        self.assertIn("notice", third["cache"])

    def test_failed_dex_is_not_cached_as_empty_success(self):
        artifact = self.artifact(
            make_apk(
                self.root / "bad.apk",
                entries={"classes.dex": b"broken https://fallback.example.org/events"},
            )
        )
        cache = self.root / "cache"
        result = analyze_artifact(artifact, self.limits, "standard", self.cancel, cache)
        self.assertTrue(
            any(
                item["stage"] == "dex_structure" and item["status"] == "PARTIAL"
                for item in result["stages"]
            )
        )
        self.assertFalse(list(cache.glob("*.json")))

    def test_split_merge_and_local_coverage_remain_explicit(self):
        artifacts = [
            self.artifact(make_apk(self.root / "base.apk")),
            self.artifact(
                make_apk(
                    self.root / "split.apk",
                    split="config.en",
                    entries={"classes.dex": make_dex()},
                )
            ),
        ]
        results = {
            item["sha256"]: analyze_artifact(item, self.limits, "standard", self.cancel)
            for item in artifacts
        }
        apps = build_apps(artifacts, results, None, self.limits, "standard")
        self.assertEqual(len(apps), 1)
        self.assertEqual(len(apps[0]["artifacts"]), 2)
        self.assertTrue(
            any(
                item["stage"] == "method_dataflow_E3"
                and item["status"] == "UNAVAILABLE"
                for item in apps[0]["coverage"]
            )
        )
        self.assertTrue(
            any(
                item["stage"] == "installed_split_inventory"
                and item["status"] == "UNAVAILABLE"
                for item in apps[0]["coverage"]
            )
        )
        self.assertIsNone(apps[0]["permissions"][0]["granted"])

    def test_budget_skips_are_visible(self):
        artifact = self.artifact(
            make_apk(self.root / "large.apk", entries={"assets/large.txt": b"x" * 4096})
        )
        limits = Limits(max_entry_bytes=1024)
        result = analyze_artifact(artifact, limits, "standard", self.cancel)
        self.assertTrue(
            any(
                item["source"] == "assets/large.txt" and item["status"] == "PARTIAL"
                for item in result["stages"]
            )
        )

    def test_xml_text_nodes_and_tails_are_scanned(self):
        apk = make_apk(
            self.root / "text.apk",
            entries={
                "res/values/strings.xml": b'<resources><string name="url">https://text.example.org/events</string> https://tail.example.org/log</resources>'
            },
        )
        result = analyze_artifact(
            self.artifact(apk), self.limits, "standard", self.cancel
        )
        hosts = {item["host"] for item in result["endpoints"]}
        self.assertTrue({"text.example.org", "tail.example.org"} <= hosts)

    def test_quick_mode_marks_unscanned_sources(self):
        apk = make_apk(
            self.root / "quick.apk",
            entries={
                "classes.dex": make_dex(),
                "assets/config.json": b'{"url":"https://asset.example.org/log"}',
            },
        )
        result = analyze_artifact(self.artifact(apk), self.limits, "quick", self.cancel)
        self.assertTrue(
            any(
                item["stage"] == "asset_strings" and item["status"] == "DEFERRED"
                for item in result["stages"]
            )
        )
        self.assertTrue(
            any(
                item["stage"] == "dex_references" and item["status"] == "DEFERRED"
                for item in result["stages"]
            )
        )
        self.assertFalse(
            any(item["evidence_level"] == "E2" for item in result["endpoints"])
        )

    def test_corrupt_zip_produces_failed_analysis(self):
        path = self.root / "broken.apk"
        path.write_bytes(b"not an archive")
        result = analyze_artifact(
            self.artifact(path), self.limits, "standard", self.cancel
        )
        self.assertTrue(any(item["status"] == "FAILED" for item in result["stages"]))

    def test_domain_sdk_rules_use_host_boundaries(self):
        apk = make_apk(
            self.root / "domain.apk",
            entries={
                "assets/urls.txt": b"https://sentry.io.evil.example/api https://errors.sentry.io/api"
            },
        )
        artifact = self.artifact(apk)
        result = analyze_artifact(artifact, self.limits, "standard", self.cancel)
        apps = build_apps(
            [artifact], {artifact["sha256"]: result}, None, self.limits, "standard"
        )
        tags = {item["host"]: item["tags"] for item in apps[0]["endpoints"]}
        self.assertNotIn(
            "sdk_telemetry_domain_candidate", tags["sentry.io.evil.example"]
        )
        self.assertIn("sdk_telemetry_domain_candidate", tags["errors.sentry.io"])

    def test_decompiled_source_scan_preserves_completion_and_cancellation(self):
        artifact = self.artifact(make_apk(self.root / "source.apk"))
        for tool_status, expected_status in (
            ("COMPLETE", "COMPLETE"),
            ("FAILED", "PARTIAL"),
            ("CANCELLED", "CANCELLED"),
        ):
            with self.subTest(tool_status=tool_status):
                output = self.root / tool_status
                cancel = threading.Event()

                def decompile(
                    arguments,
                    output=output,
                    tool_status=tool_status,
                    cancel=cancel,
                    **kwargs,
                ):
                    output.mkdir()
                    (output / "Example.java").write_text(
                        'class Example { String value = "https://source.example.org/log"; }',
                        encoding="utf-8",
                    )
                    if tool_status == "CANCELLED":
                        cancel.set()
                    return {
                        "status": tool_status,
                        "reason": None
                        if tool_status == "COMPLETE"
                        else "Decompilation interrupted",
                    }

                with patch(
                    "scripts.static_analysis.engine.run_command", side_effect=decompile
                ):
                    result = source_view(artifact, output, "jadx", self.limits, cancel)
                statuses = {item["stage"]: item["status"] for item in result["stages"]}
                self.assertEqual(statuses["decompilation"], tool_status)
                self.assertEqual(statuses["source_view"], expected_status)
                if tool_status == "CANCELLED":
                    self.assertFalse(result["endpoints"])
                else:
                    endpoint = result["endpoints"][0]
                    self.assertEqual(endpoint["host"], "source.example.org")
                    self.assertEqual(endpoint["evidence_level"], "E1")
                    self.assertEqual(endpoint["evidence"][0]["entry"], "Example.java")
                    self.assertEqual(endpoint["evidence"][0]["line"], 1)

    def test_cli_decompile_preserves_base_facts_without_successful_jadx(self):
        apk = make_apk(self.root / "input.apk", entries={"classes.dex": make_dex()})
        for tool in (None, sys.executable):
            with self.subTest(tool_available=tool is not None):
                output = self.root / ("without-tool" if tool is None else "failed-tool")
                arguments = [
                    sys.executable,
                    str(ROOT / "scripts" / "analyze.py"),
                    "scan",
                    "--apk",
                    str(apk),
                    "--mode",
                    "decompile",
                    "--output",
                    str(output),
                    "--quiet",
                ]
                if tool is not None:
                    arguments.extend(["--jadx", tool])
                completed = subprocess.run(
                    arguments, capture_output=True, text=True, timeout=15, check=False
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                report = load_report(output / "analysis.json")
                self.assertEqual(report["run"]["mode"], "decompile")
                app = report["apps"][0]
                self.assertTrue(app["manifests"])
                self.assertTrue(
                    any(item["evidence_level"] == "E2" for item in app["endpoints"])
                )
                statuses = {item["stage"]: item["status"] for item in app["coverage"]}
                self.assertEqual(statuses["source_view"], "UNAVAILABLE")
                if tool is not None:
                    self.assertEqual(statuses["decompilation"], "FAILED")
                else:
                    self.assertNotIn("decompilation", statuses)
                self.assertEqual(statuses["method_dataflow_E3"], "UNAVAILABLE")

    def test_cli_rejects_removed_mode_and_jadx_outside_decompile(self):
        apk = make_apk(self.root / "input.apk")
        for mode in ("deep", "quick", "standard"):
            with self.subTest(mode=mode):
                output = self.root / mode
                arguments = [
                    sys.executable,
                    str(ROOT / "scripts" / "analyze.py"),
                    "scan",
                    "--apk",
                    str(apk),
                    "--mode",
                    mode,
                    "--output",
                    str(output),
                ]
                if mode != "deep":
                    arguments.extend(["--jadx", sys.executable])
                completed = subprocess.run(
                    arguments, capture_output=True, text=True, timeout=15, check=False
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    "invalid choice" if mode == "deep" else "requires decompile mode",
                    completed.stderr,
                )
                self.assertFalse(output.exists())

    def test_invalid_xml_does_not_drop_other_static_facts(self):
        apk = make_apk(
            self.root / "malformed.apk",
            entries={"classes.dex": make_dex(), "res/xml/bad.xml": b"<broken>"},
        )
        result = analyze_artifact(
            self.artifact(apk), self.limits, "standard", self.cancel
        )
        self.assertIsNotNone(result["manifest"])
        self.assertTrue(result["endpoints"])
        self.assertTrue(
            any(
                item["source"] == "res/xml/bad.xml" and item["status"] == "FAILED"
                for item in result["stages"]
            )
        )

    def test_cli_query_export_and_no_overwrite(self):
        apk = make_apk(self.root / "input.apk", entries={"classes.dex": make_dex()})
        output = self.root / "result"
        arguments = [
            sys.executable,
            str(ROOT / "scripts" / "analyze.py"),
            "scan",
            "--apk",
            str(apk),
            "--output",
            str(output),
            "--quiet",
        ]
        completed = subprocess.run(
            arguments, capture_output=True, text=True, timeout=15, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "PARTIAL")
        report = load_report(output / "analysis.json")
        redacted = query(report, "endpoints", limit=1)
        self.assertNotIn("private-value", json.dumps(redacted))
        raw = query(report, "endpoints", limit=500, include_sensitive=True)
        self.assertIn("private-value", json.dumps(raw))
        queried = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "query_results.py"),
                str(output / "analysis.json"),
                "--section",
                "evidence",
                "--limit",
                "1",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(queried.returncode, 0, queried.stderr)
        self.assertEqual(len(json.loads(queried.stdout)["items"]), 1)
        exported = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "export_report.py"),
                str(output / "analysis.json"),
                "--output",
                str(self.root / "views"),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertTrue((self.root / "views" / "report.md").exists())
        original = (output / "analysis.json").read_bytes()
        repeated = subprocess.run(
            arguments, capture_output=True, text=True, timeout=10, check=False
        )
        self.assertNotEqual(repeated.returncode, 0)
        self.assertEqual((output / "analysis.json").read_bytes(), original)

    def test_command_timeout_and_cancellation(self):
        started = time.monotonic()
        result = run_command(
            [sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1
        )
        self.assertEqual(result["status"], "FAILED")
        self.assertLess(time.monotonic() - started, 3)
        cancel = threading.Event()
        cancel.set()
        result = run_command(
            [sys.executable, "-c", "import time; time.sleep(10)"], cancel=cancel
        )
        self.assertEqual(result["status"], "CANCELLED")


if __name__ == "__main__":
    unittest.main()
