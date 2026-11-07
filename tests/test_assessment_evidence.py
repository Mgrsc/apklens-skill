import copy
import html
import json
import sqlite3
import unittest
from contextlib import closing

import test_analysis_quality as quality_tests
from support import legacy_store_layout
from test_analysis_quality import ARTIFACT, application, report_for

from scripts.static_analysis.assessment import (
    markdown_text,
    prepare_assessment,
    render_assessment,
    validate_assessment,
)
from scripts.static_analysis.common import stage
from scripts.static_analysis.reports import close_report, load_report


class AssessmentEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.app = application()
        self.app["signals"] = []
        self.app["findings"] = []
        for category in ("installed_apps_api", "usage_stats", "device_identifier"):
            self.add_call(category)
        self.app["endpoints"] = [
            {
                "id": "registration-address",
                "kind": "url",
                "value": "https://device.example.test/register?token=private",
                "host": "device.example.test",
                "tags": [],
                "evidence_level": "E1",
                "evidence": [
                    {
                        "id": "registration-evidence",
                        "artifact": ARTIFACT,
                        "entry": "classes.dex",
                        "kind": "dex_string",
                    }
                ],
            }
        ]
        self.app["capabilities"] = [
            {"type": "location", "evidence_level": "E0"},
            {"type": "identifier_field", "evidence_level": "E1"},
            {"type": "installed_apps_api", "evidence_level": "E2"},
        ]
        self.app["installation"] = {
            "flags": ["HAS_CODE"],
            "shared_user": None,
            "special_access": {
                "enabled_accessibility_services": False,
                "enabled_notification_listeners": False,
                "default_input_method": False,
            },
            "appops": {"BIND_ACCESSIBILITY_SERVICE": "allow"},
            "stages": [stage("package_permissions", "COMPLETE")],
        }
        self.report = report_for([self.app])
        self.assessment = prepare_assessment(self.report)
        self.row = self.assessment["applications"][0]

    def add_call(self, category, level="E2"):
        evidence = {
            "id": category + "-evidence-" + level,
            "artifact": ARTIFACT,
            "entry": "classes.dex",
            "kind": "dex_invocation" if level == "E2" else "manifest_permission",
        }
        self.app["signals"].append(
            {
                "id": category + "-signal-" + level,
                "type": category,
                "evidence_level": level,
                "evidence": [evidence],
            }
        )
        self.app["findings"].append(
            {
                "id": category + "-finding-" + level,
                "type": "privacy_capability_candidate",
                "data_category": category,
                "evidence_level": level,
                "evidence_ids": [evidence["id"]],
            }
        )

    def reviewed(self):
        self.row["state"] = "reviewed"
        self.row["reason"] = "Available evidence was assessed; execution is unknown"
        self.row["claims"] = [
            {
                "id": category,
                "type": "direct_call",
                "text": "A direct call exists for " + category,
                "finding_ids": [category + "-finding-E2"],
                "evidence_ids": [category + "-evidence-E2"],
            }
            for category in ("installed_apps_api", "usage_stats", "device_identifier")
        ] + [
            {
                "id": "endpoint",
                "type": "static_clue",
                "text": "A registration address exists; payload association is unknown",
                "evidence_ids": ["registration-evidence"],
            }
        ]
        return self.row

    def recommendation(self, action="uninstall"):
        return {
            "action": action,
            "conditions": ["If unwanted, after preserving required data"],
            "claim_ids": ["installed_apps_api"],
            "impact": "Application functionality and unbacked local data are lost",
            "verification": "Check application state and required workflows",
            "recovery": "Reinstallation and data recovery remain unverified",
            "prerequisites": [
                {"type": kind, "status": "verified", "basis": "Captured checks"}
                for kind in ("dependency", "role", "reversibility")
            ],
        }

    def result(self):
        return validate_assessment(self.report, self.assessment)

    def test_inventory_includes_all_categories_and_untagged_endpoints(self):
        inventory = self.row.get("evidence_inventory", [])
        self.assertEqual(
            {item["key"] for item in inventory},
            {
                "privacy_capability_candidate:installed_apps_api",
                "privacy_capability_candidate:usage_stats",
                "privacy_capability_candidate:device_identifier",
                "endpoint_candidates",
            },
        )
        self.assertEqual(self.result()["validation_status"], "PASS")

    def test_reviewed_row_cannot_silently_drop_an_available_category(self):
        self.reviewed()["claims"].pop(1)
        result = self.result()
        self.assertEqual(result["validation_status"], "FAILED")
        self.assertTrue(any("usage_stats" in error for error in result["errors"]))

    def test_untagged_address_requires_a_claim_or_explicit_deferral(self):
        self.reviewed()["claims"].pop()
        result = self.result()
        self.assertEqual(result["validation_status"], "FAILED")
        self.assertTrue(
            any("endpoint_candidates" in error for error in result["errors"])
        )

    def test_explicit_deferral_is_visible_in_validation_and_rendering(self):
        self.reviewed()["claims"].pop(1)
        self.row["deferred_evidence"] = [
            {
                "key": "privacy_capability_candidate:usage_stats",
                "reason": "The caller and time-window fields need further inspection",
            }
        ]
        result = self.result()
        self.assertEqual(result["validation_status"], "PASS")
        self.assertEqual(result["evidence_review_counts"]["deferred"], 1)
        rendered = render_assessment(self.report, self.assessment)
        self.assertIn("usage&#95;stats", rendered)
        self.assertIn("time&#45;window", rendered)

    def test_declaration_cannot_hide_a_stronger_direct_call(self):
        self.add_call("usage_stats", "E0")
        self.assessment = prepare_assessment(self.report)
        self.row = self.assessment["applications"][0]
        self.reviewed()["claims"][1] = {
            "id": "usage_stats",
            "type": "declaration",
            "text": "Only declared access was assessed",
            "finding_ids": ["usage_stats-finding-E0"],
        }
        self.assertEqual(self.result()["validation_status"], "FAILED")

    def test_shared_evidence_ids_do_not_promote_a_lower_level_claim(self):
        self.add_call("usage_stats", "E0")
        self.app["findings"][1]["evidence_ids"].append("usage_stats-evidence-E0")
        self.assessment = prepare_assessment(self.report)
        self.row = self.assessment["applications"][0]
        self.reviewed()["claims"][1] = {
            "id": "usage_stats",
            "type": "declaration",
            "text": "Only declared access was assessed",
            "finding_ids": ["usage_stats-finding-E0"],
            "evidence_ids": ["usage_stats-evidence-E0"],
        }
        result = self.result()
        self.assertEqual(result["validation_status"], "FAILED")
        self.assertTrue(any("usage_stats" in error for error in result["errors"]))

    def test_evidence_only_claims_can_cover_their_source_category(self):
        for claim in self.reviewed()["claims"]:
            claim.pop("finding_ids", None)
        self.assertEqual(self.result()["validation_status"], "PASS")

    def test_legacy_rows_cannot_bypass_review_by_omitting_inventory(self):
        self.reviewed()
        self.row.pop("evidence_inventory", None)
        self.row.pop("deferred_evidence", None)
        self.assertEqual(self.result()["validation_status"], "PASS")
        self.row["claims"].pop(1)
        self.assertEqual(self.result()["validation_status"], "FAILED")

    def test_inventory_is_derived_and_cannot_be_edited_to_hide_evidence(self):
        self.reviewed()
        self.row["evidence_inventory"] = []
        self.assertEqual(self.result()["validation_status"], "FAILED")

    def test_invalid_deferrals_fail_without_crashing(self):
        self.reviewed()
        for value in (
            {},
            [{"key": [], "reason": "Invalid"}],
            [{"key": "unknown", "reason": "Invalid"}],
            [{"key": "endpoint_candidates", "reason": "Already claimed"}],
        ):
            with self.subTest(value=value):
                self.row["deferred_evidence"] = value
                self.assertEqual(self.result()["validation_status"], "FAILED")

    def test_unknown_roles_cannot_be_verified_despite_allowed_appops(self):
        self.reviewed()["recommendations"] = [self.recommendation()]
        self.assertEqual(self.result()["validation_status"], "PASS")
        access = self.app["installation"]["special_access"]
        access["enabled_accessibility_services"] = None
        self.row["context"] = prepare_assessment(self.report)["applications"][0][
            "context"
        ]
        self.assertEqual(self.result()["validation_status"], "FAILED")

    def test_missing_roles_require_review_before_uninstall(self):
        self.app["installation"]["special_access"] = {}
        self.assessment = prepare_assessment(self.report)
        self.row = self.assessment["applications"][0]
        recommendation = self.recommendation()
        recommendation["prerequisites"] = []
        self.reviewed()["recommendations"] = [recommendation]
        self.assertEqual(self.result()["validation_status"], "FAILED")

    def test_restriction_can_keep_unknown_roles_explicit(self):
        self.app["installation"]["special_access"]["enabled_accessibility_services"] = (
            None
        )
        self.assessment = prepare_assessment(self.report)
        self.row = self.assessment["applications"][0]
        recommendation = self.recommendation("retain_restrict")
        for prerequisite in recommendation["prerequisites"]:
            prerequisite["status"] = "unverified"
            prerequisite["basis"] = "Role and restoration checks are still missing"
        self.reviewed()["recommendations"] = [recommendation]
        self.assertEqual(self.result()["validation_status"], "PASS")
        rendered = render_assessment(self.report, self.assessment)
        self.assertIn("unverified", rendered)
        self.assertIn("restoration checks", rendered)

    def test_statistics_preserve_mixed_capability_levels(self):
        statistics = self.result().get("source_statistics", {})
        self.assertEqual(
            statistics.get("capabilities"),
            {
                "unit": "capability_record",
                "records": 3,
                "by_evidence_level": {"E0": 1, "E1": 1, "E2": 1},
            },
        )
        self.reviewed()
        rendered = render_assessment(self.report, self.assessment)
        self.assertIn('"capability_record"', rendered)
        self.assertIn('"E2": 1', rendered)

    def test_prepared_statistics_and_inventory_do_not_mutate_the_source(self):
        before = copy.deepcopy(self.report)
        self.reviewed()
        self.assertEqual(self.result()["validation_status"], "PASS")
        render_assessment(self.report, self.assessment, "zh-CN")
        self.assertEqual(self.report, before)

    def test_inventory_samples_are_bounded_and_disclose_unshown_records(self):
        source = self.app["findings"][0]
        self.app["findings"].extend(
            [{**source, "id": "additional-" + str(index)} for index in range(6)]
        )
        inventory = prepare_assessment(self.report)["applications"][0][
            "evidence_inventory"
        ]
        item = next(
            item for item in inventory if item["key"].endswith(":installed_apps_api")
        )
        self.assertEqual(item["records"], 7)
        self.assertEqual(len(item["record_id_sample"]), 3)
        self.assertTrue(item["record_ids_truncated"])

    def test_invalid_claims_cannot_satisfy_category_coverage(self):
        self.reviewed()["claims"][1]["type"] = "declaration"
        result = self.result()
        self.assertEqual(result["validation_status"], "FAILED")
        self.assertEqual(result["evidence_review_counts"]["unreviewed"], 1)

    def test_duplicate_and_empty_deferrals_are_rejected(self):
        self.reviewed()["claims"].pop(1)
        item = {
            "key": "privacy_capability_candidate:usage_stats",
            "reason": "Pending source inspection",
        }
        self.row["deferred_evidence"] = [item, item]
        self.assertEqual(self.result()["validation_status"], "FAILED")
        self.row["deferred_evidence"] = [{**item, "reason": " "}]
        self.assertEqual(self.result()["validation_status"], "FAILED")

    def test_known_active_roles_require_dependency_review(self):
        self.app["installation"]["special_access"]["default_input_method"] = True
        self.assessment = prepare_assessment(self.report)
        self.row = self.assessment["applications"][0]
        recommendation = self.recommendation()
        self.reviewed()["recommendations"] = [recommendation]
        self.assertEqual(self.result()["validation_status"], "PASS")
        recommendation["prerequisites"].pop(0)
        self.assertEqual(self.result()["validation_status"], "FAILED")

    def test_pending_and_deferred_rows_disclose_unreviewed_evidence(self):
        self.assertEqual(self.result()["evidence_review_counts"]["unreviewed"], 4)
        for state in ("pending", "deferred"):
            self.row.update(state=state, reason="Evidence is awaiting review")
            self.assertEqual(self.result()["validation_status"], "PASS")
            self.assertIn("unreviewed", render_assessment(self.report, self.assessment))

    def test_markdown_escaping_preserves_readable_ids_without_encoding_entities_twice(
        self,
    ):
        text = "package_name finding-id 'quoted' [value] <tag>"
        self.assertEqual(html.unescape(markdown_text(text)), text)

    def test_rendering_prioritizes_supported_conclusions_without_completing_review(
        self,
    ):
        self.reviewed()
        self.row.update(state="deferred", reason="Remaining categories need inspection")
        self.row["claims"] = self.row["claims"][:2]
        self.row["claims"].append({**self.row["claims"][0], "id": "second-location"})
        pending = application("com.example.pending")
        self.report["apps"].insert(0, pending)
        self.assessment["applications"].insert(
            0, prepare_assessment(report_for([pending]))["applications"][0]
        )
        self.assessment["facts"] = prepare_assessment(self.report)["facts"]
        before = copy.deepcopy(self.assessment)
        for language in ("en", "zh-CN"):
            with self.subTest(language=language):
                rendered = render_assessment(self.report, self.assessment, language)
                readable = html.unescape(rendered)
                self.assertLess(
                    readable.index(self.row["claims"][0]["text"]),
                    readable.index("com.example.pending"),
                )
                self.assertLess(
                    readable.index(self.row["reason"]), rendered.index("```json")
                )
                if language == "zh-CN":
                    self.assertIn("已有证据结论：1 个应用组", readable)
                    self.assertIn("应用评估标记 reviewed：0 个", readable)
                    self.assertIn("已回应 2", readable)
                else:
                    self.assertIn(
                        "Application groups with evidence claims: 1", readable
                    )
                    self.assertIn("Application groups marked reviewed: 0", readable)
                    self.assertIn("covered 2", readable)
        self.assertEqual(self.assessment, before)

    def test_rendering_untouched_register_does_not_invent_conclusions(self):
        missing = application("com.example.noapk", False)
        self.report["apps"].append(missing)
        self.assessment["applications"].append(
            prepare_assessment(report_for([missing]))["applications"][0]
        )
        self.assessment["facts"] = prepare_assessment(self.report)["facts"]
        rendered = html.unescape(
            render_assessment(self.report, self.assessment, "zh-CN")
        )
        self.assertIn("已有证据结论：0 个应用组", rendered)
        self.assertIn("已回应 0", rendered)
        self.assertIn("尚未记录证据结论或处置建议", rendered)
        self.assertIn("com.example.target", rendered)
        self.assertIn("com.example.noapk", rendered)
        self.assertIn("metadata_only", rendered)
        self.assertIn("No APK artifacts are available", rendered)

    def test_rendering_keeps_category_deferrals_visible_with_reviewed_state(self):
        self.reviewed()["claims"].pop(1)
        self.row["deferred_evidence"] = [
            {
                "key": "privacy_capability_candidate:usage_stats",
                "reason": "Missing caller arguments; reopen when inputs are available",
            }
        ]
        rendered = html.unescape(
            render_assessment(self.report, self.assessment, "zh-CN")
        )
        self.assertIn("应用评估标记 reviewed：1 个", rendered)
        self.assertIn("明确延期 1", rendered)
        self.assertIn(self.row["deferred_evidence"][0]["reason"], rendered)
        self.assertLess(
            rendered.index(self.row["deferred_evidence"][0]["reason"]),
            rendered.index("```json"),
        )

    def test_rendering_snapshot_claims_do_not_count_as_evidence_categories(self):
        permission = "android.permission.READ_PHONE_STATE"
        self.app["permissions"] = [
            {"name": permission, "granted": False, "grant_source": "snapshot"}
        ]
        self.assessment = prepare_assessment(self.report)
        self.row = self.assessment["applications"][0]
        self.row["claims"] = [
            {
                "id": "grant",
                "type": "snapshot_grant",
                "text": "The captured permission was not granted",
                "permission": permission,
                "granted": False,
                "grant_source": "snapshot",
                "grant_scope": "app",
            }
        ]
        rendered = html.unescape(
            render_assessment(self.report, self.assessment, "zh-CN")
        )
        self.assertIn("已有证据结论：1 个应用组", rendered)
        self.assertIn("已回应 0", rendered)
        self.assertIn("未核对 4", rendered)
        self.assertIn(self.row["claims"][0]["text"], rendered)

    def test_rendering_remaining_groups_preserves_identity_and_escapes_input(self):
        injected = "![remote]|<script>unsafe</script> (https://example.test/tracker)"
        self.app["package"] = injected
        other = copy.deepcopy(self.app)
        other.update(id="second-group", user=10, version_code="2")
        self.report["apps"].append(other)
        self.assessment = prepare_assessment(self.report)
        for row in self.assessment["applications"]:
            row["reason"] = injected
        rendered = render_assessment(self.report, self.assessment)
        readable = html.unescape(rendered)
        rows = [line for line in rendered.splitlines() if line.startswith("| &#33;")]
        self.assertEqual(len(rows), 2)
        for line, row in zip(rows, self.assessment["applications"]):
            self.assertEqual(line.count("|"), 5)
            cells = [html.unescape(cell).strip() for cell in line.split("|")]
            self.assertIn(row["identity"]["app_id"], cells[1])
            self.assertEqual(
                cells[2],
                f"{row['identity']['user']} / {row['identity']['version_code']}",
            )
        for row in self.assessment["applications"]:
            self.assertIn(row["identity"]["app_id"], readable)
            self.assertIn(str(row["identity"]["user"]), readable)
            self.assertIn(str(row["identity"]["version_code"]), readable)
        self.assertNotIn("![remote]", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("https://example.test", rendered)
        self.assertIn("&#124;", rendered)

    def test_rendering_without_claims_preserves_deferred_actions_and_prerequisites(
        self,
    ):
        recommendation = self.recommendation("defer")
        recommendation["claim_ids"] = []
        for item in recommendation["prerequisites"]:
            item.update(status="unverified", basis="Missing dependency and role inputs")
        self.row.update(
            state="deferred",
            reason="Awaiting device context before recommending any change",
            recommendations=[recommendation],
        )
        before = copy.deepcopy(self.assessment)
        for language in ("en", "zh-CN"):
            with self.subTest(language=language):
                rendered = html.unescape(
                    render_assessment(self.report, self.assessment, language)
                )
                for key in ("impact", "verification", "recovery"):
                    self.assertIn(recommendation[key], rendered)
                for condition in recommendation["conditions"]:
                    self.assertIn(condition, rendered)
                for item in recommendation["prerequisites"]:
                    self.assertIn(item["type"], rendered)
                    self.assertIn(item["status"], rendered)
                    self.assertIn(item["basis"], rendered)
                self.assertLess(
                    rendered.index(recommendation["impact"]), rendered.index("```json")
                )
                if language == "zh-CN":
                    self.assertIn("已有证据结论：0 个应用组", rendered)
                else:
                    self.assertIn(
                        "Application groups with evidence claims: 0", rendered
                    )
        self.assertEqual(self.assessment, before)

    def test_json_current_and_legacy_sqlite_assessments_match_without_source_writes(
        self,
    ):
        self.reviewed()
        expected = self.result()
        harness = quality_tests.AnalysisQualityTests()
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        store, stored = harness.persist(self.report)
        json_path = harness.root / "source.json"
        json_path.write_text(json.dumps(self.report), encoding="utf-8")
        self.assertEqual(validate_assessment(stored, self.assessment), expected)
        self.assertEqual(
            validate_assessment(load_report(json_path), self.assessment), expected
        )
        for version in (1, 2, 3, 4):
            with self.subTest(version=version):
                path = harness.root / f"source-{version}.sqlite3"
                with closing(sqlite3.connect(path)) as connection:
                    store.connection.backup(connection)
                    if version != 4:
                        legacy_store_layout(connection, version)
                before = path.read_bytes()
                report = load_report(path)
                try:
                    self.assertEqual(
                        prepare_assessment(report), prepare_assessment(self.report)
                    )
                    self.assertEqual(
                        validate_assessment(report, self.assessment), expected
                    )
                    self.assertEqual(
                        render_assessment(report, self.assessment),
                        render_assessment(self.report, self.assessment),
                    )
                finally:
                    close_report(report)
                self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
