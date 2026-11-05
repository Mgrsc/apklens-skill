import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import make_apk, make_dex

from scripts.static_analysis.common import Limits
from scripts.static_analysis.endpoints import EndpointCollector
from scripts.static_analysis.reports import close_report, load_report, query, summary

ROOT = Path(__file__).resolve().parents[1]


class EndpointSelectionTests(unittest.TestCase):
    def collector(self, maximum=50000):
        return EndpointCollector(Limits(max_results=maximum))

    def test_late_explicit_network_candidates_replace_low_confidence_samples(self):
        collector = self.collector(2)
        source = {"kind": "dex_string", "entry": "classes.dex", "string_index": 3}
        collector.add_text(
            " ".join(f"android.fake.property{index}.value" for index in range(100)),
            source,
        )
        collector.add_text("https://private.internal/report 192.168.2.7", source)
        self.assertEqual(
            {item["candidate_class"] for item in collector.results()},
            {"explicit_url", "ip_literal"},
        )
        self.assertEqual(len(collector.results()), 2)
        selection = collector.candidate_summary()
        self.assertEqual(selection["observed_occurrences"]["low_confidence"], 100)
        self.assertEqual(selection["low_confidence_sample_count"], 0)
        self.assertTrue(selection["low_confidence_samples_truncated"])
        self.assertTrue(collector.partial)
        self.assertFalse(collector.truncated)

    def test_explicit_candidates_replace_latest_contextual_hosts_first(self):
        collector = self.collector(2)
        source = {"kind": "asset_strings", "entry": "assets/settings.json"}
        for value in (
            "host=first.internal",
            "host=second.internal",
            "https://explicit.internal/a",
        ):
            collector.add_text(value, source)
        self.assertEqual(
            {item["host"] for item in collector.results()},
            {"first.internal", "explicit.internal"},
        )
        self.assertEqual(collector.candidate_summary()["evicted_contextual_records"], 1)
        collector.add_text("https://later.internal/b", source)
        collector.add_text("https://dropped.internal/c", source)
        self.assertEqual(
            {item["host"] for item in collector.results()},
            {"explicit.internal", "later.internal"},
        )
        self.assertEqual(
            collector.candidate_summary()["dropped_network_occurrences"],
            {"explicit_url": 1},
        )

    def test_same_network_clues_survive_different_noise_source_orders(self):
        for kinds in (
            ("native_strings", "asset_strings", "resources"),
            ("resources", "native_strings", "asset_strings"),
        ):
            with self.subTest(kinds=kinds):
                collector = self.collector(3)
                for kind in kinds:
                    collector.add_text(
                        " ".join(f"this.object{index}.property" for index in range(80)),
                        {"kind": kind, "entry": "entry"},
                    )
                collector.add_text(
                    "https://service.internal/a //private.example/x 10.0.0.2",
                    {"kind": "dex_string", "entry": "classes.dex"},
                )
                self.assertEqual(
                    {item["candidate_class"] for item in collector.results()},
                    {"explicit_url", "ip_literal"},
                )
                self.assertEqual(len(collector.results()), 3)
                self.assertEqual(
                    set(collector.candidate_summary()["by_source"]),
                    {*kinds, "dex_string"},
                )

    def test_contextual_internal_unicode_and_real_country_suffix_hosts(self):
        collector = self.collector()
        for value in (
            'host="api.internal"',
            "server=bücher.example",
            "url=https://localhost/a",
            "endpoint=service.so",
        ):
            collector.add_text(value, {"kind": "asset_strings", "entry": "config"})
        collector.add_text(
            "api.private",
            {"kind": "xml", "attribute": "host", "entry": "res/config.xml"},
        )
        self.assertEqual(
            {item["host"] for item in collector.results()},
            {
                "api.internal",
                "xn--bcher-kva.example",
                "localhost",
                "service.so",
                "api.private",
            },
        )

    def test_identifier_noise_remains_unknown_with_bounded_provenance(self):
        collector = self.collector()
        source = {"kind": "dex_string", "entry": "classes.dex", "string_index": 1}
        collector.add_text(
            "android.permission.INTERNET android.intent.action.SEARCH 0.00.toFixed com.example.RealHost",
            source,
            [{"method": "LExample;->run()V", "instruction_offset": 0}],
        )
        self.assertEqual(collector.results(), [])
        samples = collector.candidate_summary()["low_confidence_samples"]
        self.assertEqual(len(samples), 4)
        self.assertTrue(
            all(
                sample["classification"] == "low_confidence"
                and sample["evidence"]["string_index"] == 1
                for sample in samples
            )
        )
        self.assertFalse(collector.partial)
        for _ in range(100):
            collector.add_text("bare.internal", source)
        self.assertEqual(len(collector.samples), 32)
        self.assertTrue(collector.partial)

    def test_ip_idn_templates_and_encoded_urls_preserve_network_intent(self):
        collector = self.collector()
        source = {"kind": "asset_strings", "entry": "config"}
        for value in (
            "https://bücher.example/a",
            "//bücher.example/a",
            "https://${host}/api",
            "https%3A%2F%2Fprivate.internal%2Fupload",
            "aHR0cHM6Ly9iYXNlNjQuZXhhbXBsZS5vcmcvY29sbGVjdA==",
            "127.0.0.1 2001:db8::1",
            "https://[2001:db8::2]/report",
            "//127.0.0.2/report",
        ):
            collector.add_text(value, source)
        hosts = {item["host"] for item in collector.results()}
        self.assertTrue(
            {
                "xn--bcher-kva.example",
                "private.internal",
                "base64.example.org",
                "127.0.0.1",
                "127.0.0.2",
                "2001:db8::1",
                "2001:db8::2",
            }.issubset(hosts)
        )
        self.assertTrue(
            any(item["kind"] == "unresolved_template" for item in collector.results())
        )
        self.assertEqual(
            sum(item["host"] == "2001:db8::2" for item in collector.results()), 1
        )

    def test_invalid_url_does_not_reenter_as_an_inner_host_or_ip(self):
        collector = self.collector()
        collector.add_text(
            "https://127.0.0.1:99999/a https://bad_host.example/a", {"entry": "entry"}
        )
        self.assertEqual(collector.results(), [])
        self.assertEqual(collector.candidate_summary()["observed_occurrences"], {})

    def test_summary_sqlite_json_and_domains_disclose_candidate_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            apk = make_apk(
                root / "input.apk",
                entries={
                    "res/xml/network_security_config.xml": b"<network-security-config><domain-config><domain>service.private</domain></domain-config></network-security-config>",
                    "classes.dex": make_dex(
                        extra_strings=["android.permission.INTERNET"] * 40
                    ),
                },
            )
            output = root / "output"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/analyze.py"),
                    "scan",
                    "--apk",
                    str(apk),
                    "--output",
                    str(output),
                    "--no-cache",
                    "--quiet",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary_value = json.loads((output / "summary.json").read_text())
            selection = summary_value["facts"]["endpoints"]["selection"]
            self.assertEqual(selection["policy_versions"], [1])
            self.assertGreaterEqual(
                selection["observed_occurrences"]["low_confidence"], 40
            )
            self.assertTrue(selection["low_confidence_samples_truncated"])
            self.assertNotIn(
                "android.permission.internet", (output / "domains.txt").read_text()
            )
            self.assertIn("service.private", (output / "domains.txt").read_text())
            markdown = (output / "report.md").read_text()
            self.assertNotIn("all valid host and bare domain candidates", markdown)
            self.assertIn("bare dotted tokens remain unknown", markdown)
            reports = [
                load_report(output / name)
                for name in ("analysis.sqlite3", "analysis.json")
            ]
            try:
                self.assertEqual(
                    summary(reports[0])["facts"], summary(reports[1])["facts"]
                )
                for report in reports:
                    coverage = query(report, "coverage", limit=100)
                    self.assertTrue(
                        any(
                            item.get("metrics", {}).get("candidate_selection")
                            for item in coverage["items"]
                        )
                    )
            finally:
                for report in reports:
                    close_report(report)
