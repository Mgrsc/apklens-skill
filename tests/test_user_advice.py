import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from support import legacy_store_layout

from scripts.static_analysis.common import json_chunks, stage
from scripts.static_analysis.reports import (
    close_report,
    load_report,
    markdown,
    query,
    summary,
)
from scripts.static_analysis.storage import (
    APP_SECTIONS,
    AnalysisStore,
    Apps,
    FindingIds,
    Records,
)

ROOT = Path(__file__).resolve().parents[1]


class UserAdviceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def app(self, package="com.example.optional", finding_count=8):
        findings = [
            {
                "id": f"finding-{index}",
                "type": "privacy_capability_candidate",
                "evidence_level": "E2",
                "evidence_ids": [f"evidence-{index}"],
            }
            for index in range(finding_count)
        ]
        return {
            "id": package,
            "package": package,
            "version_code": "1",
            "user": 10,
            "status": "PARTIAL",
            "artifacts": [],
            "permissions": [],
            "manifests": [],
            "capabilities": [],
            "endpoints": [],
            "sdks": [],
            "signals": [],
            "methods": [],
            "fields": [],
            "findings": findings,
            "coverage": [stage("dex_dataflow", "PARTIAL", reason="Model gap")],
            "priority": {"score": 50, "reasons": ["clipboard_api"]},
            "recommendations": [
                {
                    "action": "review_static_evidence",
                    "finding_ids": [item["id"] for item in findings],
                    "requires_device_change": False,
                },
                {
                    "action": "review_granted_permissions_in_system_settings",
                    "requires_device_change": True,
                    "execution": "manual_only",
                },
            ],
            "installation": {
                "user": 10,
                "uid": "10123",
                "app_id": "10123",
                "version_code": "1",
                "installer": "com.example.store",
                "is_system": True,
                "flags": ["SYSTEM", "HAS_CODE"],
                "shared_user": "android.uid.example",
                "appops": {"GET_USAGE_STATS": "default", "CAMERA": "foreground"},
                "special_access": {
                    "default_input_method": True,
                    "enabled_notification_listeners": None,
                    "enabled_accessibility_services": False,
                },
                "remote_paths": ["/system/app/private/base.apk"],
                "permissions": {},
                "stages": [
                    stage("package_permissions", "COMPLETE"),
                    stage("appops_snapshot", "COMPLETE"),
                ],
            },
        }

    def report(self, apps):
        return {
            "schema_version": 1,
            "engine_version": "1.1.3",
            "run": {"id": "advice-test", "status": "PARTIAL", "mode": "standard"},
            "stages": [],
            "apps": apps,
            "artifacts": [],
            "totals": {"apps": len(apps), "endpoints": 0},
            "limitations": ["Runtime behavior is unverified"],
        }

    def persisted_report(self, *apps):
        store = AnalysisStore(self.root / "analysis.sqlite3")
        self.addCleanup(store.close)
        for app in apps:
            app = copy.deepcopy(app)
            sections = {key: app[key] for key in APP_SECTIONS}
            store.begin_app(app)
            for key, values in sections.items():
                app[key].extend(values)
            app["recommendations"][0]["finding_ids"] = FindingIds(app["findings"])
            store.save_app(app)
        report = self.report(Apps(store))
        store.save_report(report)
        return store, report

    def test_app_query_exposes_installation_and_bounded_recommendations(self):
        app = self.app()
        before = copy.deepcopy(app)
        row = query(self.report([app]), "apps")["items"][0]
        self.assertTrue(row["installation"]["is_system"])
        self.assertEqual(row["installation"]["user"], 10)
        self.assertEqual(row["installation"]["shared_user"], "android.uid.example")
        self.assertNotIn("remote_paths", row["installation"])
        self.assertNotIn("permissions", row["installation"])
        recommendation = row["recommendations"][0]
        self.assertEqual(recommendation["finding_count"], 8)
        self.assertEqual(
            recommendation["finding_id_sample"],
            ["finding-0", "finding-1", "finding-2"],
        )
        self.assertTrue(recommendation["finding_ids_truncated"])
        self.assertNotIn("finding_ids", recommendation)
        self.assertEqual(app, before)

    def test_system_classification_requires_complete_nonempty_flags(self):
        for flags, status, expected in (
            (["SYSTEM", "HAS_CODE"], "COMPLETE", True),
            (["HAS_CODE"], "COMPLETE", False),
            (["SYSTEM"], "PARTIAL", None),
            (["HAS_CODE"], "FAILED", None),
            ([], "COMPLETE", None),
            (None, "COMPLETE", None),
        ):
            with self.subTest(flags=flags, status=status):
                app = self.app()
                app["installation"]["flags"] = flags
                app["installation"]["is_system"] = False
                app["installation"]["stages"][0]["status"] = status
                context = query(self.report([app]), "apps")["items"][0]["installation"]
                self.assertIs(context["is_system"], expected)
                self.assertEqual(context["package_metadata_status"], status)

    def test_missing_metadata_stage_does_not_trust_false_system_marker(self):
        app = self.app()
        app["installation"].update(is_system=False, flags=["HAS_CODE"], stages=[])
        context = query(self.report([app]), "apps")["items"][0]["installation"]
        self.assertIsNone(context["is_system"])
        self.assertEqual(context["package_metadata_status"], "UNAVAILABLE")

    def test_local_and_missing_snapshots_remain_unknown(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                app = self.app()
                if missing:
                    del app["installation"]
                else:
                    app["installation"] = None
                row = query(self.report([app]), "apps")["items"][0]
                self.assertIsNone(row["installation"])

    def test_appops_default_and_unknown_special_access_are_preserved(self):
        context = query(self.report([self.app()]), "apps")["items"][0]["installation"]
        self.assertEqual(context["appops"]["GET_USAGE_STATS"], "default")
        self.assertEqual(context["appops"]["CAMERA"], "foreground")
        self.assertIsNone(context["special_access"]["enabled_notification_listeners"])
        self.assertTrue(context["special_access"]["default_input_method"])
        self.assertFalse(context["special_access"]["enabled_accessibility_services"])

    def test_advice_context_preserves_gaps_without_inventing_remediation(self):
        report = self.report([self.app()])
        row = query(report, "apps")["items"][0]
        self.assertEqual(row["status"], "PARTIAL")
        self.assertEqual(
            [item["action"] for item in row["recommendations"]],
            [
                "review_static_evidence",
                "review_granted_permissions_in_system_settings",
            ],
        )
        self.assertEqual(query(report, "coverage")["items"][0]["reason"], "Model gap")
        finding = query(report, "findings", identity="finding-0")["items"][0]
        self.assertEqual(finding["evidence_level"], "E2")
        self.assertEqual(finding["evidence_ids"], ["evidence-0"])

    def test_sqlite_json_and_legacy_queries_match_without_rewriting_sources(self):
        app = self.app()
        expected = query(self.report([app]), "apps")
        store, report = self.persisted_report(app)
        json_path = self.root / "analysis.json"
        json_path.write_text("".join(json_chunks(report)), encoding="utf-8")
        self.assertEqual(query(load_report(json_path), "apps"), expected)
        self.assertEqual(query(report, "apps"), expected)
        for version in (1, 2, 3):
            with self.subTest(version=version):
                path = self.root / f"version-{version}.sqlite3"
                connection = sqlite3.connect(path)
                store.connection.backup(connection)
                legacy_store_layout(connection, version)
                if version == 1:
                    connection.execute(
                        "DELETE FROM metadata WHERE key LIKE 'app_view:%'"
                    )
                connection.commit()
                connection.close()
                before = path.read_bytes()
                loaded = load_report(path)
                try:
                    self.assertEqual(query(loaded, "apps"), expected)
                    self.assertEqual(markdown(loaded), markdown(self.report([app])))
                finally:
                    close_report(loaded)
                self.assertEqual(path.read_bytes(), before)

    def test_indexed_query_does_not_decode_findings_for_recommendation_sample(self):
        _, report = self.persisted_report(self.app(finding_count=100))
        with patch.object(
            Records, "page", side_effect=AssertionError("Unexpected fact decoding")
        ):
            row = query(report, "apps", limit=1)["items"][0]
        self.assertEqual(row["recommendations"][0]["finding_count"], 100)
        self.assertEqual(len(row["recommendations"][0]["finding_id_sample"]), 3)

    def test_summary_stays_lightweight_and_does_not_expose_installation(self):
        _, report = self.persisted_report(self.app())
        with patch.object(
            FindingIds, "__iter__", side_effect=AssertionError("Unexpected ID scan")
        ):
            row = summary(report)["apps"][0]
        self.assertNotIn("installation", row)
        self.assertNotIn("recommendations", row)

    def test_indexed_pagination_only_reads_selected_recommendation_samples(self):
        store, report = self.persisted_report(
            self.app("com.example.first"),
            self.app("com.example.second"),
            self.app("com.example.third"),
        )
        for options, expected_calls in (
            ({"offset": 1, "limit": 1}, 1),
            ({"identity": "com.example.third", "limit": 1}, 1),
            ({"identity": "absent", "limit": 1}, 0),
            ({"offset": 3, "limit": 1}, 0),
        ):
            with self.subTest(options=options):
                with patch.object(
                    store, "finding_ids", wraps=store.finding_ids
                ) as identities:
                    result = query(report, "apps", **options)
                self.assertEqual(identities.call_count, expected_calls)
                self.assertEqual(len(result["items"]), expected_calls)

    def test_markdown_renders_review_context_and_respects_row_limit(self):
        first = self.app()
        second = self.app("com.example.other")
        report = markdown(self.report([first, second]), limit=1)
        section = report.split("## User Actions and Review Context", 1)[1].split(
            "## Application Overview", 1
        )[0]
        self.assertIn("com.example.optional", section)
        self.assertNotIn("com.example.other", section)
        self.assertIn("android.uid.example", section)
        self.assertIn("default_input_method=True", section)
        self.assertIn("finding-0, finding-1, finding-2", section)
        self.assertIn("PARTIAL", section)
        self.assertNotIn("{{", report)

    def test_zero_findings_and_missing_recommendations_still_show_context(self):
        app = self.app(finding_count=0)
        app["installation"] = None
        del app["recommendations"]
        row = query(self.report([app]), "apps")["items"][0]
        self.assertEqual(row["recommendations"], [])
        report = markdown(self.report([app]))
        section = report.split("## User Actions and Review Context", 1)[1].split(
            "## Application Overview", 1
        )[0]
        self.assertIn("com.example.optional", section)
        self.assertIn("Unknown", section)

    def test_cli_queries_and_reexports_saved_context_without_rescanning(self):
        store, _ = self.persisted_report(self.app())
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "query_results.py"),
                str(store.path),
                "--section",
                "apps",
                "--package",
                "com.example.optional",
                "--limit",
                "1",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        row = json.loads(completed.stdout)["items"][0]
        self.assertTrue(row["installation"]["is_system"])
        output = self.root / "export"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "export_report.py"),
                str(store.path),
                "--output",
                str(output),
                "--view-limit",
                "1",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        rendered = (output / "report.md").read_text(encoding="utf-8")
        self.assertIn("## User Actions and Review Context", rendered)
        self.assertIn("android.uid.example", rendered)


if __name__ == "__main__":
    unittest.main()
