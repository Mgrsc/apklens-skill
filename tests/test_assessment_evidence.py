import copy
import html
import json
import sqlite3
import unittest
from contextlib import closing

import test_analysis_quality as quality_tests
from support import legacy_store_layout
from test_analysis_quality import ARTIFACT, application, report_for

from scripts.static_analysis.advice_reporting import (
    markdown_text,
    render_assessment,
    reporting_source_key,
)
from scripts.static_analysis.assessment import (
    prepare_assessment,
    validate_assessment,
)
from scripts.static_analysis.common import stage
from scripts.static_analysis.reports import close_report, load_report


def rendered_text(report, assessment, language="en"):
    return "\n".join(render_assessment(report, assessment, language).values())


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
        rendered = rendered_text(self.report, self.assessment)
        self.assertIn(self.row["deferred_evidence"][0]["reason"], rendered)
        self.assertIn("time-window", rendered)

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
        rendered = rendered_text(self.report, self.assessment)
        self.assertIn("not verified", rendered)
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
        rendered = rendered_text(self.report, self.assessment)
        self.assertNotIn('"capability_record"', rendered)
        self.assertNotIn("```json", rendered)
        self.assertEqual(self.result()["source_statistics"], statistics)

    def test_prepared_statistics_and_inventory_do_not_mutate_the_source(self):
        before = copy.deepcopy(self.report)
        self.reviewed()
        self.assertEqual(self.result()["validation_status"], "PASS")
        rendered_text(self.report, self.assessment, "zh-CN")
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
            rendered = rendered_text(self.report, self.assessment)
            self.assertIn("Some applications or evidence still await review", rendered)
            self.assertNotIn("unreviewed", rendered)

    def test_markdown_escaping_preserves_readable_ids_without_encoding_entities_twice(
        self,
    ):
        text = "package_name finding-id 'quoted' (value) [tag] <script>"
        escaped = markdown_text(text)
        self.assertIn("package_name", escaped)
        self.assertIn("finding-id", escaped)
        self.assertIn("'quoted'", escaped)
        self.assertIn("(value)", escaped)
        self.assertNotIn("&#46;", escaped)
        self.assertNotIn("&#95;", escaped)
        self.assertNotIn("&#45;", escaped)
        self.assertEqual(html.unescape(escaped), text)

    def test_rendering_uses_application_sections_without_raw_context_or_repeated_advice(
        self,
    ):
        self.app["sdks"] = [
            {
                "id": "sdk-1",
                "name": "Fresco",
                "purpose": "foundation",
                "record_kind": "component",
                "match_basis": "namespace",
                "evidence_level": "E1",
                "evidence": [{"id": "sdk-ev", "kind": "dex_class_definition"}],
            }
        ]
        self.app["installation"]["appops"].update(
            CAMERA="allow",
            FINE_LOCATION="ignore",
            READ_CONTACTS="deny",
        )
        self.report = report_for([self.app])
        self.assessment = prepare_assessment(self.report)
        self.row = self.assessment["applications"][0]
        self.reviewed()["recommendations"] = [self.recommendation("retain_restrict")]
        for language in ("en", "zh-CN"):
            with self.subTest(language=language):
                rendered = rendered_text(self.report, self.assessment, language)
                self.assertNotIn("{'app_id'", rendered)
                self.assertNotIn("&#123;", rendered)
                self.assertNotIn("&#46;", rendered)
                self.assertIn("com.example.target", rendered)
                self.assertIn("## com.example.target", rendered)
                for token in (
                    "`CAMERA`",
                    "`FINE_LOCATION`",
                    "`READ_CONTACTS`",
                    "`Fresco`",
                    "retain_restrict",
                    "```json",
                    "<details>",
                ):
                    self.assertNotIn(token, rendered)
                self.assertFalse(
                    any(line.startswith("|") for line in rendered.splitlines())
                )
                recommendation = self.row["recommendations"][0]
                self.assertEqual(rendered.count(recommendation["impact"]), 1)
                for claim in self.row["claims"]:
                    self.assertEqual(rendered.count(claim["text"]), 1)

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
                rendered = rendered_text(self.report, self.assessment, language)
                readable = html.unescape(rendered)
                self.assertNotIn("com.example.pending", readable)
                self.assertIn(self.row["reason"], readable)
                self.assertEqual(readable.count(self.row["claims"][0]["text"]), 1)
                self.assertIn("assessment.json", readable)
                self.assertIn("delivery-summary.json", readable)
                if language == "zh-CN":
                    self.assertIn("2 个应用组，其中 1 个已有证据结论", readable)
                    self.assertIn("部分应用或证据尚未核查", readable)
                else:
                    self.assertIn(
                        "2 application groups; evidence conclusions have been recorded for 1",
                        readable,
                    )
                    self.assertIn(
                        "Some applications or evidence still await review", readable
                    )
        self.assertEqual(self.assessment, before)

    def test_rendering_untouched_register_does_not_invent_conclusions(self):
        missing = application("com.example.noapk", False)
        self.report["apps"].append(missing)
        self.assessment["applications"].append(
            prepare_assessment(report_for([missing]))["applications"][0]
        )
        self.assessment["facts"] = prepare_assessment(self.report)["facts"]
        rendered = html.unescape(rendered_text(self.report, self.assessment, "zh-CN"))
        self.assertIn("2 个应用组，其中 0 个已有证据结论", rendered)
        self.assertIn("当前尚未记录证据结论", rendered)
        self.assertIn("当前尚未记录处置建议", rendered)
        self.assertIn("1 个应用组没有 APK", rendered)
        for token in (
            "com.example.target",
            "com.example.noapk",
            "metadata_only",
            "```json",
        ):
            self.assertNotIn(token, rendered)
        self.assertEqual(len(self.assessment["applications"]), 2)

    def test_rendering_keeps_category_deferrals_visible_with_reviewed_state(self):
        self.reviewed()["claims"].pop(1)
        self.row["deferred_evidence"] = [
            {
                "key": "privacy_capability_candidate:usage_stats",
                "reason": "Missing caller arguments; reopen when inputs are available",
            }
        ]
        rendered = html.unescape(rendered_text(self.report, self.assessment, "zh-CN"))
        self.assertIn("部分应用或证据尚未核查", rendered)
        self.assertIn(self.row["deferred_evidence"][0]["reason"], rendered)
        self.assertEqual(self.result()["evidence_review_counts"]["deferred"], 1)

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
        rendered = html.unescape(rendered_text(self.report, self.assessment, "zh-CN"))
        self.assertIn("1 个应用组，其中 1 个已有证据结论", rendered)
        self.assertEqual(self.result()["evidence_review_counts"]["unreviewed"], 4)
        self.assertIn(self.row["claims"][0]["text"], rendered)
        self.assertNotIn(permission, rendered)
        self.assertIn("未授予", rendered)

    def test_shared_uid_grants_without_apks_keep_their_scope_visible(self):
        permission = "android.permission.READ_PHONE_STATE"
        self.app.update(artifacts=[], signals=[], findings=[], endpoints=[])
        self.app["permissions"] = [
            {"name": permission, "granted": True, "grant_source": "shared_uid_snapshot"}
        ]
        self.assessment = prepare_assessment(self.report)
        self.row = self.assessment["applications"][0]
        self.row["claims"] = [
            {
                "id": "shared-grant",
                "type": "snapshot_grant",
                "text": "The captured phone-state permission record",
                "permission": permission,
                "granted": True,
                "grant_source": "shared_uid_snapshot",
                "grant_scope": "shared_uid",
            }
        ]
        for language, expected in (
            ("en", "applies to a shared UID"),
            ("zh-CN", "属于共享 UID 范围"),
        ):
            with self.subTest(language=language):
                rendered = rendered_text(self.report, self.assessment, language)
                self.assertIn(expected, rendered)
                self.assertNotIn(permission, rendered)
                self.assertNotIn(
                    "Code analysis for this application is incomplete", rendered
                )
                self.assertNotIn("该应用代码分析未全部完成", rendered)
        self.assertEqual(self.result()["review_counts"]["metadata_only"], 1)

    def test_rendering_explicit_deferrals_preserves_identity_and_escapes_input(self):
        injected = "![remote]|<script>unsafe</script> (https://example.test/tracker)"
        self.app["package"] = injected
        other = copy.deepcopy(self.app)
        other.update(id="second-group", user=10, version_code="2")
        self.report["apps"].append(other)
        self.assessment = prepare_assessment(self.report)
        for row in self.assessment["applications"]:
            row.update(state="deferred", reason=injected)
        self.assessment["reporting"] = {
            "schema_version": 1,
            "source_key": reporting_source_key(self.report, self.assessment),
            "groups": [
                {
                    "id": f"scope-{index}",
                    "title": row["identity"]["package"],
                    "summary": "A recorded review gap affects this decision",
                    "reason": "The missing scope must remain visible",
                    "kind": "attention",
                    "placement": "details",
                    "refs": [
                        {"app_id": row["identity"]["app_id"], "kind": "review_scope"}
                    ],
                }
                for index, row in enumerate(self.assessment["applications"])
            ],
            "routine": [],
        }
        rendered = rendered_text(self.report, self.assessment)
        readable = html.unescape(rendered)
        details = render_assessment(self.report, self.assessment)["report-details.md"]
        self.assertEqual(details.count('<a id="issue-scope-'), 2)
        for index in (0, 1):
            self.assertIn(f"](#issue-scope-{index})", details)
        for row in self.assessment["applications"]:
            self.assertNotIn(row["identity"]["app_id"], readable)
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
                    rendered_text(self.report, self.assessment, language)
                )
                for key in ("impact", "verification", "recovery"):
                    self.assertIn(recommendation[key], rendered)
                for condition in recommendation["conditions"]:
                    self.assertIn(condition, rendered)
                for item in recommendation["prerequisites"]:
                    self.assertIn(item["basis"], rendered)
                self.assertEqual(rendered.count(recommendation["impact"]), 1)
                if language == "zh-CN":
                    self.assertIn("1 个应用组，其中 0 个已有证据结论", rendered)
                    self.assertIn("尚未核实", rendered)
                else:
                    self.assertIn(
                        "1 application groups; evidence conclusions have been recorded for 0",
                        rendered,
                    )
                    self.assertIn("not verified", rendered)
        self.assertEqual(self.assessment, before)

    def test_large_pending_register_is_not_expanded_into_user_advice(self):
        self.report = report_for(
            [application(f"com.example.awaiting{index}") for index in range(525)]
        )
        self.assessment = prepare_assessment(self.report)
        before = copy.deepcopy(self.assessment)
        for language in ("en", "zh-CN"):
            with self.subTest(language=language):
                rendered = rendered_text(self.report, self.assessment, language)
                self.assertIn("525", rendered)
                self.assertNotIn("com.example.awaiting", rendered)
                self.assertNotIn(
                    "report-details.md",
                    render_assessment(self.report, self.assessment, language),
                )
                self.assertNotIn("```", rendered)
                self.assertNotIn("<details>", rendered)
                self.assertIn("[", rendered)
                self.assertIn("assessment.json", rendered)
                self.assertIn("delivery-summary.json", rendered)
        self.assertEqual(self.assessment, before)
        self.assertEqual(self.result()["review_counts"]["pending"], 525)

    def test_duplicate_findings_keep_distinct_limitations_and_unreferenced_claims(self):
        self.reviewed()
        original = self.row["claims"][0]
        self.row["claims"].extend(
            [
                {**original, "id": "same-conclusion"},
                {
                    **original,
                    "id": "limited-conclusion",
                    "limitations": "Caller arguments remain unknown",
                },
            ]
        )
        self.row["recommendations"] = [self.recommendation("retain_restrict")]
        before = copy.deepcopy(self.assessment)
        rendered = rendered_text(self.report, self.assessment)
        self.assertEqual(rendered.count(original["text"]), 2)
        self.assertEqual(rendered.count("Caller arguments remain unknown"), 1)
        for claim in self.row["claims"][1:4]:
            self.assertEqual(rendered.count(claim["text"]), 1)
        self.assertEqual(self.assessment, before)
        self.assertEqual(self.result()["delivery_summary"]["claim_count"], 6)

    def test_identical_visible_identities_keep_distinct_record_ids(self):
        other = copy.deepcopy(self.app)
        other["id"] = "second-artifact-group"
        self.report["apps"].append(other)
        self.assessment = prepare_assessment(self.report)
        for row in self.assessment["applications"]:
            row.update(state="deferred", reason="Artifact identity needs inspection")
            row["recommendations"] = [self.recommendation("defer")]
            row["recommendations"][0]["claim_ids"] = []
        rendered = rendered_text(self.report, self.assessment)
        for row in self.assessment["applications"]:
            self.assertIn(row["identity"]["app_id"], rendered)

    def test_optional_display_name_keeps_package_identity_and_escapes_markup(self):
        self.reviewed()["display_name"] = (
            "Example app ![remote](https://example.test/x)"
        )
        before = copy.deepcopy(self.assessment)
        rendered = rendered_text(self.report, self.assessment)
        self.assertIn("## Example app", rendered)
        self.assertIn("(com.example.target) | Version", rendered)
        self.assertNotIn("![remote]", rendered)
        self.assertNotIn("https://example.test", rendered)
        self.assertEqual(self.assessment, before)
        for invalid in (None, [], " "):
            with self.subTest(invalid=invalid):
                self.row["display_name"] = invalid
                self.assertEqual(self.result()["validation_status"], "FAILED")

    def test_stop_reason_is_translated_without_upgrading_analysis_or_review(self):
        self.reviewed()
        self.report["run"]["stop_reason"] = "analysis_timeout"
        before = copy.deepcopy(self.report)
        for language, expected in (
            ("en", "the offline analysis time budget was reached"),
            ("zh-CN", "已达到离线分析时间预算"),
        ):
            with self.subTest(language=language):
                rendered = rendered_text(self.report, self.assessment, language)
                self.assertIn(expected, rendered)
                self.assertNotIn("analysis_timeout", rendered)
                self.assertNotIn("PARTIAL", rendered)
        self.assertEqual(self.report, before)
        self.assertEqual(self.result()["analysis_status"], "PARTIAL")

    def test_empty_review_keeps_its_scope_without_inventing_findings(self):
        self.app["findings"] = []
        self.app["endpoints"] = []
        self.assessment = prepare_assessment(self.report)
        row = self.assessment["applications"][0]
        row.update(
            state="reviewed", reason="No supported conclusion in the inspected scope"
        )
        rendered = rendered_text(self.report, self.assessment)
        self.assertNotIn(row["reason"], rendered)
        self.assertNotIn(
            "report-details.md", render_assessment(self.report, self.assessment)
        )
        self.assertIn("No evidence conclusions have been recorded", rendered)
        self.assertEqual(self.result()["delivery_summary"]["claim_count"], 0)

    def test_rendering_does_not_truncate_supported_conclusions(self):
        self.reviewed()
        source = self.row["claims"][0]
        self.row["claims"].extend(
            {**source, "id": f"additional-{index}", "text": f"Supported issue {index}."}
            for index in range(50)
        )
        rendered = rendered_text(self.report, self.assessment)
        for claim in self.row["claims"]:
            self.assertIn(claim["text"], rendered)

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
                        rendered_text(report, self.assessment),
                        rendered_text(self.report, self.assessment),
                    )
                finally:
                    close_report(report)
                self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
