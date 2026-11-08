import copy
import hashlib
import html
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

import test_analysis_quality as quality_tests
from support import legacy_store_layout
from test_analysis_quality import application, report_for

from scripts.static_analysis.advice_reporting import (
    recommendation_key,
    render_assessment,
    reporting_source_key,
    validate_delivery,
)
from scripts.static_analysis.assessment import prepare_assessment, validate_assessment
from scripts.static_analysis.common import AnalysisError
from scripts.static_analysis.endpoints import sanitized
from scripts.static_analysis.reports import close_report, load_report

ROOT = Path(__file__).resolve().parents[1]


def reviewed_assessment(count=1, claims=True):
    apps = [application(f"com.example.item{index}") for index in range(count)]
    if not claims:
        for app in apps:
            app["findings"] = []
            app["signals"] = []
    report = report_for(apps)
    assessment = prepare_assessment(report)
    for row in assessment["applications"]:
        app_id = row["identity"]["app_id"]
        row.update(
            state="reviewed",
            reason="Available evidence was inspected within this review scope",
        )
        if claims:
            row["claims"] = [
                {
                    "id": "call",
                    "type": "direct_call",
                    "text": "An installed-application enumeration call exists",
                    "limitations": "Execution, trigger conditions and upload remain unverified",
                    "finding_ids": [app_id + "-finding"],
                    "evidence_ids": [app_id + "-evidence"],
                }
            ]
    return report, assessment


def recommendation(action="retain_restrict"):
    return {
        "action": action,
        "claim_ids": ["call"],
        "conditions": ["Only if the affected optional feature is unused"],
        "impact": "The affected feature may become unavailable",
        "verification": "Check the current setting and required workflows",
        "recovery": "Record the original setting; restoration remains unverified",
        "prerequisites": [
            {
                "type": "reversibility",
                "status": "unverified",
                "basis": "Restoration has not been tested",
            }
        ],
    }


def references(report, assessment, app_id=None):
    return [
        ref
        for ref in validate_delivery(report, assessment)["reporting"][
            "available_references"
        ]
        if ref["kind"] != "review_scope" and (app_id is None or ref["app_id"] == app_id)
    ]


def issue(identity, refs, kind="attention", placement="main"):
    return {
        "id": identity,
        "title": "Review the application-enumeration capability",
        "summary": "The recorded capability needs a decision within the stated conditions",
        "reason": "The finding affects the requested privacy decision",
        "kind": kind,
        "placement": placement,
        "refs": refs,
    }


def bind_plan(report, assessment, groups=()):
    groups = list(groups)
    assigned = [ref for group in groups for ref in group["refs"]]
    remaining = [ref for ref in references(report, assessment) if ref not in assigned]
    assessment["reporting"] = {
        "schema_version": 1,
        "source_key": reporting_source_key(report, assessment),
        "groups": groups,
        "routine": [
            {
                "refs": remaining,
                "reason": "Routine material does not establish a separate user decision",
            }
        ]
        if remaining
        else [],
    }
    return assessment["reporting"]


class AdviceReportingTests(unittest.TestCase):
    def test_525_reviewed_rows_without_findings_do_not_expand(self):
        report, assessment = reviewed_assessment(525, claims=False)
        for planned in (False, True):
            if planned:
                bind_plan(report, assessment)
            for language in ("en", "zh-CN"):
                with self.subTest(planned=planned, language=language):
                    documents = render_assessment(report, assessment, language)
                    self.assertEqual(set(documents), {"user-advice.md"})
                    self.assertIn("525", documents["user-advice.md"])
                    self.assertNotIn("com.example.item", documents["user-advice.md"])
                    self.assertLess(len(documents["user-advice.md"].splitlines()), 50)
        self.assertTrue(
            validate_delivery(report, assessment)["delivery_summary"]["review_complete"]
        )

    def test_525_routine_claims_and_retain_advice_stay_in_ledger(self):
        report, assessment = reviewed_assessment(525)
        for row in assessment["applications"]:
            row["recommendations"] = [recommendation("retain")]
        bind_plan(report, assessment)
        before = copy.deepcopy(assessment)
        result = validate_delivery(report, assessment)
        self.assertEqual(result["reporting"]["status"], "ready")
        self.assertEqual(result["reporting"]["counts"]["routine_records"], 1050)
        documents = render_assessment(report, assessment)
        self.assertEqual(set(documents), {"user-advice.md"})
        self.assertNotIn("com.example.item", documents["user-advice.md"])
        self.assertEqual(assessment, before)

    def test_525_members_share_one_problem_and_one_conditional_action(self):
        report, assessment = reviewed_assessment(525)
        for row in assessment["applications"]:
            row["recommendations"] = [recommendation()]
        bind_plan(
            report,
            assessment,
            [
                issue(
                    "shared-enumeration", references(report, assessment), kind="action"
                )
            ],
        )
        before = copy.deepcopy(assessment)
        result = validate_delivery(report, assessment)
        self.assertEqual(result["reporting"]["status"], "ready")
        self.assertEqual(result["reporting"]["counts"]["application_groups"], 525)
        for language in ("en", "zh-CN"):
            documents = render_assessment(report, assessment, language)
            main, details = documents["user-advice.md"], documents["report-details.md"]
            self.assertLess(len(main.splitlines()), 60)
            self.assertIn("report-details.md#issue-shared-enumeration", main)
            self.assertEqual(
                details.count(assessment["applications"][0]["claims"][0]["text"]), 1
            )
            self.assertEqual(details.count(recommendation()["impact"]), 1)
            for row in assessment["applications"]:
                self.assertIn(row["identity"]["package"] + " |", details)
        self.assertEqual(assessment, before)

    def test_different_action_conditions_impacts_and_recovery_form_variants(self):
        report, assessment = reviewed_assessment(4)
        for index, row in enumerate(assessment["applications"]):
            row["recommendations"] = [recommendation()]
            if index:
                field = ("conditions", "impact", "recovery")[index - 1]
                row["recommendations"][0][field] = (
                    ["A distinct condition"]
                    if field == "conditions"
                    else f"A distinct {field}"
                )
        bind_plan(
            report,
            assessment,
            [issue("variants", references(report, assessment), kind="action")],
        )
        details = render_assessment(report, assessment)["report-details.md"]
        self.assertEqual(details.count("### "), 4)
        for row in assessment["applications"]:
            self.assertIn(row["identity"]["package"], details)
            value = row["recommendations"][0]
            for field in ("impact", "recovery"):
                self.assertIn(value[field], details)

    def test_shared_uid_and_application_grants_remain_distinct(self):
        report, original = reviewed_assessment(2)
        for index, app in enumerate(report["apps"]):
            app["permissions"] = [
                {
                    "name": "android.permission.READ_PHONE_STATE",
                    "declaration": "snapshot_only",
                    "granted": True,
                    "grant_source": "snapshot" if index == 0 else "shared_uid_snapshot",
                }
            ]
        assessment = prepare_assessment(report)
        for index, row in enumerate(assessment["applications"]):
            row.update(
                state="reviewed", reason=original["applications"][index]["reason"]
            )
            row["claims"] = original["applications"][index]["claims"] + [
                {
                    "id": "grant",
                    "type": "snapshot_grant",
                    "text": "The captured phone-state grant is present",
                    "permission": "android.permission.READ_PHONE_STATE",
                    "granted": True,
                    "grant_source": "snapshot" if index == 0 else "shared_uid_snapshot",
                    "grant_scope": "app" if index == 0 else "shared_uid",
                }
            ]
        bind_plan(
            report, assessment, [issue("grant-scopes", references(report, assessment))]
        )
        details = render_assessment(report, assessment)["report-details.md"]
        self.assertEqual(details.count("The captured phone-state grant is present"), 2)
        self.assertEqual(details.count("applies to a shared UID"), 1)
        for row in assessment["applications"]:
            self.assertIn(row["identity"]["package"] + " |", details)

    def test_distinct_captured_roles_prevent_collapsing_identical_advice(self):
        report, original = reviewed_assessment(2)
        report["apps"][1]["installation"] = {"shared_user": "android.uid.shared"}
        assessment = prepare_assessment(report)
        for index, row in enumerate(assessment["applications"]):
            row.update(
                state="reviewed",
                reason=original["applications"][index]["reason"],
                claims=original["applications"][index]["claims"],
            )
            row["recommendations"] = [recommendation("retain")]
        bind_plan(
            report,
            assessment,
            [issue("role-boundaries", references(report, assessment))],
        )
        details = render_assessment(report, assessment)["report-details.md"]
        self.assertEqual(details.count(recommendation()["impact"]), 2)

    def test_retain_and_defer_are_selected_by_explicit_decisions(self):
        report, assessment = reviewed_assessment(3)
        for row in assessment["applications"]:
            row["recommendations"] = [recommendation("retain")]
        assessment["applications"][1].update(
            state="deferred",
            reason="Current authorization determines whether a change is useful",
        )
        assessment["applications"][1]["recommendations"] = [recommendation("defer")]
        groups = [
            issue(
                f"decision-{index}",
                references(
                    report,
                    assessment,
                    assessment["applications"][index]["identity"]["app_id"],
                ),
            )
            for index in (0, 1)
        ]
        bind_plan(report, assessment, groups)
        result = validate_delivery(report, assessment)
        self.assertEqual(result["reporting"]["counts"]["action_groups"], 0)
        main = render_assessment(report, assessment)["user-advice.md"]
        self.assertIn("Keep the existing configuration", main)
        self.assertIn("Defer changes until", main)
        self.assertNotIn("com.example.item2 |", main)

    def test_few_important_gaps_survive_many_routine_claims(self):
        report, assessment = reviewed_assessment(40)
        row = assessment["applications"][-1]
        row.update(
            state="deferred",
            reason="Caller inputs determine whether a restriction is appropriate",
            claims=[],
        )
        row["deferred_evidence"] = [
            {
                "key": "privacy_capability_candidate",
                "reason": "Inspect the caller inputs before recommending a change",
            }
        ]
        bind_plan(
            report,
            assessment,
            [
                issue(
                    "caller-inputs",
                    references(report, assessment, row["identity"]["app_id"]),
                )
            ],
        )
        main = render_assessment(report, assessment)["user-advice.md"]
        self.assertIn(row["deferred_evidence"][0]["reason"], main)
        self.assertNotIn(
            assessment["applications"][0]["identity"]["package"] + " |", main
        )
        self.assertFalse(
            validate_delivery(report, assessment)["delivery_summary"]["review_complete"]
        )

    def test_525_independent_issues_remain_reachable_without_truncation(self):
        report, assessment = reviewed_assessment(525)
        available = references(report, assessment)
        groups = [
            issue(
                f"question-{index}",
                [ref],
                placement="main" if index == 0 else "details",
            )
            for index, ref in enumerate(available)
        ]
        bind_plan(report, assessment, groups)
        documents = render_assessment(report, assessment)
        self.assertLess(len(documents["user-advice.md"].splitlines()), 70)
        self.assertIn(
            "Issues: 525; affected application groups: 525", documents["user-advice.md"]
        )
        self.assertEqual(
            documents["report-details.md"].count('<a id="issue-question-'), 524
        )
        self.assertIn('id="issue-question-524"', documents["report-details.md"])
        self.assertIn("## Contents", documents["report-details.md"])
        self.assertIn("](#issue-question-524)", documents["report-details.md"])
        for row in assessment["applications"]:
            self.assertIn(
                row["identity"]["package"] + " |", "\n".join(documents.values())
            )

    def test_shared_claim_supports_multiple_actions_without_duplicate_ownership(self):
        report, assessment = reviewed_assessment()
        row = assessment["applications"][0]
        row["recommendations"] = [
            recommendation(),
            {
                **recommendation(),
                "conditions": ["A different optional workflow is unused"],
            },
        ]
        refs = references(report, assessment)
        bind_plan(
            report,
            assessment,
            [
                issue("first-action", refs[:2], kind="action"),
                issue("second-action", refs[2:], kind="action"),
            ],
        )
        result = validate_delivery(report, assessment)
        self.assertEqual(result["reporting"]["status"], "ready")
        self.assertEqual(result["reporting"]["counts"]["application_groups"], 1)
        main = render_assessment(report, assessment)["user-advice.md"]
        self.assertEqual(main.count(row["claims"][0]["limitations"]), 2)

    def test_action_dependencies_keep_limitations_even_when_claim_is_routine(self):
        report, assessment = reviewed_assessment()
        row = assessment["applications"][0]
        row["recommendations"] = [recommendation()]
        refs = references(report, assessment)
        bind_plan(
            report,
            assessment,
            [
                issue(
                    "restriction",
                    [ref for ref in refs if ref["kind"] == "recommendation"],
                    kind="action",
                )
            ],
        )
        main = render_assessment(report, assessment)["user-advice.md"]
        self.assertIn(row["claims"][0]["limitations"], main)
        self.assertIn(recommendation()["prerequisites"][0]["basis"], main)

    def test_identical_duplicate_recommendations_keep_original_counts(self):
        report, assessment = reviewed_assessment()
        row = assessment["applications"][0]
        row["recommendations"] = [recommendation(), recommendation()]
        refs = references(report, assessment)
        self.assertEqual(sum(ref["kind"] == "recommendation" for ref in refs), 1)
        bind_plan(report, assessment, [issue("restriction", refs, kind="action")])
        self.assertEqual(
            validate_delivery(report, assessment)["delivery_summary"][
                "recommendation_count"
            ],
            2,
        )
        main = render_assessment(report, assessment)["user-advice.md"]
        self.assertEqual(main.count(recommendation()["impact"]), 1)
        self.assertEqual(len(row["recommendations"]), 2)

    def test_reordering_recommendations_does_not_change_their_keys(self):
        first = recommendation()
        second = {**first, "recovery": "A distinct recovery requirement"}
        key = recommendation_key("app", first)
        self.assertEqual(
            key, recommendation_key("app", dict(reversed(list(first.items()))))
        )
        self.assertNotEqual(key, recommendation_key("other-app", first))
        self.assertNotEqual(key, recommendation_key("app", second))

    def test_url_redaction_is_idempotent_for_persisted_report_content(self):
        for value in (
            "https://example.test/path?token=secret#private",
            "https://example.test/path#private",
            "https://user:password@example.test/path?token=secret",
            "Already redacted: https://example.test/path?<redacted>",
            "https://example.test/path?<redacted>#<redacted>",
        ):
            with self.subTest(value=value):
                cleaned = sanitized(value)
                self.assertEqual(sanitized(cleaned), cleaned)
                self.assertNotIn("secret", cleaned)
                self.assertNotIn("password", cleaned)

    def test_source_changes_invalidate_editorial_decisions(self):
        report, assessment = reviewed_assessment()
        assessment["applications"][0]["recommendations"] = [recommendation("retain")]
        bind_plan(report, assessment)
        mutations = [
            lambda value: value["applications"][0].update(
                reason="Revised review scope"
            ),
            lambda value: value["applications"][0]["claims"][0].update(
                text="Revised supported wording"
            ),
            lambda value: value["applications"][0]["recommendations"][0].update(
                impact="A revised impact"
            ),
            lambda value: value["applications"][0].update(
                display_name="Verified label"
            ),
        ]
        for mutation in mutations:
            value = copy.deepcopy(assessment)
            mutation(value)
            with self.subTest(mutation=mutation):
                result = validate_delivery(report, value)
                self.assertEqual(result["validation_status"], "PASS")
                self.assertEqual(result["reporting"]["status"], "invalid")
                with self.assertRaises(AnalysisError):
                    render_assessment(report, value)
        report["run"]["stop_reason"] = "analysis_timeout"
        self.assertEqual(
            validate_delivery(report, assessment)["reporting"]["status"], "invalid"
        )

    def test_incomplete_or_duplicate_routing_is_rejected(self):
        report, assessment = reviewed_assessment()
        refs = references(report, assessment)
        bind_plan(report, assessment, [issue("only-issue", refs)])
        for mutation in (
            lambda plan: plan.update(groups=[]),
            lambda plan: plan["groups"][0]["refs"].append(refs[0]),
            lambda plan: plan["groups"].append(
                {**copy.deepcopy(plan["groups"][0]), "id": "second-issue"}
            ),
        ):
            value = copy.deepcopy(assessment)
            mutation(value["reporting"])
            self.assertEqual(
                validate_delivery(report, value)["reporting"]["status"], "invalid"
            )

    def test_unknown_and_cross_application_references_are_rejected(self):
        report, assessment = reviewed_assessment(2)
        for row in assessment["applications"]:
            row["recommendations"] = [recommendation("retain")]
        bind_plan(report, assessment)
        foreign = next(
            ref
            for ref in references(report, assessment)
            if ref["kind"] == "recommendation"
        )
        for changes in (
            {"key": "unknown"},
            {"app_id": "outside-task"},
            {"app_id": assessment["applications"][1]["identity"]["app_id"]},
        ):
            value = copy.deepcopy(assessment)
            value["reporting"]["routine"][0]["refs"].append({**foreign, **changes})
            self.assertEqual(
                validate_delivery(report, value)["reporting"]["status"], "invalid"
            )

    def test_device_changes_cannot_be_archived_or_labeled_attention(self):
        report, assessment = reviewed_assessment()
        assessment["applications"][0]["recommendations"] = [recommendation()]
        bind_plan(report, assessment)
        result = validate_delivery(report, assessment)
        self.assertEqual(result["validation_status"], "PASS")
        self.assertIn("cannot be routine", " ".join(result["reporting"]["errors"]))
        bind_plan(
            report, assessment, [issue("hidden-action", references(report, assessment))]
        )
        self.assertEqual(
            validate_delivery(report, assessment)["reporting"]["status"], "invalid"
        )

    def test_malformed_plans_fail_without_crashing(self):
        report, assessment = reviewed_assessment()
        bind_plan(
            report, assessment, [issue("only-issue", references(report, assessment))]
        )
        mutations = [
            lambda value: value.update(reporting=None),
            lambda value: value.update(reporting=[]),
            lambda value: value["reporting"].update(schema_version=True),
            lambda value: value["reporting"].update(schema_version=[]),
            lambda value: value["reporting"].update(groups={}),
            lambda value: value["reporting"].update(routine="invalid"),
            lambda value: value["reporting"]["groups"].append(None),
            lambda value: value["reporting"]["groups"][0].update(
                id='<img src="remote">'
            ),
            lambda value: value["reporting"]["groups"][0].update(kind=[]),
            lambda value: value["reporting"]["groups"][0].update(placement={}),
            lambda value: value["reporting"]["groups"][0].update(summary=" "),
            lambda value: value["reporting"]["groups"][0].update(
                refs=[None, {}, {"app_id": [], "kind": "claim"}]
            ),
            lambda value: value["reporting"]["groups"][0]["refs"][0].update(key=[]),
        ]
        for mutation in mutations:
            value = copy.deepcopy(assessment)
            mutation(value)
            with self.subTest(mutation=mutation):
                self.assertEqual(
                    validate_delivery(report, value)["reporting"]["status"], "invalid"
                )

    def test_invalid_source_does_not_reach_reporting_projection(self):
        report, assessment = reviewed_assessment()
        assessment["applications"] = None
        result = validate_delivery(report, assessment)
        self.assertEqual(result["validation_status"], "FAILED")
        self.assertEqual(result["reporting"]["status"], "invalid")

    def test_reporting_completion_does_not_complete_source_review(self):
        report, assessment = reviewed_assessment()
        assessment["applications"][0].update(
            state="deferred", reason="More caller inspection is required"
        )
        bind_plan(
            report, assessment, [issue("call-scope", references(report, assessment))]
        )
        result = validate_delivery(report, assessment)
        self.assertEqual(result["reporting"]["status"], "ready")
        self.assertFalse(result["delivery_summary"]["review_complete"])
        self.assertEqual(result["delivery_summary"]["analysis_status"], "PARTIAL")
        assessment["applications"][0]["recommendations"] = [recommendation()]
        self.assertEqual(
            validate_delivery(report, assessment)["validation_status"], "FAILED"
        )

    def test_old_ledger_keeps_real_content_in_uncurated_details(self):
        report, assessment = reviewed_assessment()
        before = copy.deepcopy(assessment)
        result = validate_delivery(report, assessment)
        self.assertEqual(result["reporting"]["status"], "missing")
        documents = render_assessment(report, assessment)
        text = assessment["applications"][0]["claims"][0]["text"]
        self.assertNotIn(text, documents["user-advice.md"])
        self.assertIn(text, documents["report-details.md"])
        self.assertEqual(assessment, before)

    def test_no_apk_and_all_pending_remain_scope_only(self):
        for artifacts in (True, False):
            report = report_for([application("com.example.pending", artifacts)])
            assessment = prepare_assessment(report)
            bind_plan(report, assessment)
            result = validate_delivery(report, assessment)
            self.assertEqual(result["reporting"]["status"], "ready")
            self.assertFalse(result["delivery_summary"]["review_complete"])
            documents = render_assessment(report, assessment)
            self.assertEqual(set(documents), {"user-advice.md"})
            self.assertNotIn("com.example.pending", documents["user-advice.md"])

    def test_generated_links_and_explicit_anchors_are_reachable(self):
        report, assessment = reviewed_assessment(3)
        refs = references(report, assessment)
        bind_plan(
            report, assessment, [issue("local", [refs[0]]), issue("shared", refs[1:])]
        )
        documents = render_assessment(report, assessment)
        for name, content in documents.items():
            for target in re.findall(r"\]\(([^)]+)\)", content):
                file_name, separator, anchor = target.partition("#")
                file_name = file_name or name
                if file_name in {"assessment.json", "delivery-summary.json"}:
                    continue
                self.assertIn(file_name, documents)
                if separator:
                    self.assertIn(f'id="{anchor}"', documents[file_name])

    def test_markup_secrets_and_identity_collisions_are_preserved_safely(self):
        report, assessment = reviewed_assessment(2)
        report["apps"][1]["package"] = report["apps"][0]["package"]
        assessment = prepare_assessment(report)
        for index, row in enumerate(assessment["applications"]):
            row.update(state="deferred", reason="Scope needs inspection")
            row["display_name"] = "![remote](https://remote.test/x?token=secret-value)"
            row["claims"] = [
                {
                    "id": "call",
                    "type": "direct_call",
                    "text": "<script>unsafe</script>",
                    "finding_ids": [report["apps"][index]["id"] + "-finding"],
                    "evidence_ids": [report["apps"][index]["id"] + "-evidence"],
                }
            ]
        group = issue("safe-anchor", references(report, assessment))
        group["title"] = "![remote](https://remote.test/x)"
        bind_plan(report, assessment, [group])
        before = copy.deepcopy(assessment)
        documents = render_assessment(report, assessment)
        rendered = "\n".join(documents.values())
        for forbidden in (
            "![remote]",
            "<script>",
            "secret-value",
            "https://remote.test",
        ):
            self.assertNotIn(forbidden, rendered)
        for row in assessment["applications"]:
            self.assertIn(row["identity"]["app_id"], html.unescape(rendered))
        self.assertEqual(assessment, before)
        cleaned = sanitized(assessment)
        self.assertEqual(
            reporting_source_key(report, cleaned), assessment["reporting"]["source_key"]
        )

    def test_current_json_and_legacy_sqlite_have_identical_ready_delivery(self):
        report, assessment = reviewed_assessment()
        bind_plan(report, assessment, [issue("call", references(report, assessment))])
        expected = validate_delivery(report, assessment)
        harness = quality_tests.AnalysisQualityTests()
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        store, _ = harness.persist(report)
        source_json = harness.root / "source.json"
        source_json.write_text(json.dumps(report))
        self.assertEqual(
            validate_delivery(load_report(source_json), assessment), expected
        )
        for version in (1, 2, 3, 4):
            path = harness.root / f"source-{version}.sqlite3"
            with closing(sqlite3.connect(path)) as connection:
                store.connection.backup(connection)
                if version != 4:
                    legacy_store_layout(connection, version)
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            opened = load_report(path)
            try:
                self.assertEqual(validate_delivery(opened, assessment), expected)
                self.assertEqual(
                    render_assessment(opened, assessment),
                    render_assessment(report, assessment),
                )
            finally:
                close_report(opened)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)


class AdviceDeliveryCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.report, self.assessment = reviewed_assessment(2)
        self.source = self.root / "analysis.json"
        self.ledger = self.root / "assessment.json"
        self.source.write_text(json.dumps(self.report))

    def invoke(self, action, output=None):
        self.ledger.write_text(json.dumps(self.assessment))
        command = [
            sys.executable,
            str(ROOT / "scripts/assess_results.py"),
            action,
            str(self.source),
        ]
        if action != "prepare":
            command.extend(["--assessment", str(self.ledger)])
        if output is not None:
            command.extend(["--output", str(output)])
        return subprocess.run(
            command, capture_output=True, text=True, timeout=15, check=False
        )

    def test_prepare_validate_render_and_optional_files(self):
        prepared = self.invoke("prepare", self.root / "prepared")
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self.assertEqual(
            json.loads(prepared.stdout)["delivery_summary"]["reporting_status"],
            "missing",
        )
        bind_plan(
            self.report,
            self.assessment,
            [issue("shared", references(self.report, self.assessment))],
        )
        validated = self.invoke("validate")
        self.assertEqual(validated.returncode, 0, validated.stderr)
        before = self.source.read_bytes(), self.ledger.read_bytes()
        output = self.root / "rendered"
        rendered = self.invoke("render", output)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        result = json.loads(rendered.stdout)
        self.assertEqual(
            set(result["files"]),
            {
                "assessment.json",
                "delivery-summary.json",
                "user-advice.md",
                "report-details.md",
            },
        )
        self.assertEqual(
            json.loads((output / "delivery-summary.json").read_text()),
            result["delivery_summary"],
        )
        self.assertEqual((self.source.read_bytes(), self.ledger.read_bytes()), before)
        self.assertEqual(
            validate_delivery(
                self.report, json.loads((output / "assessment.json").read_text())
            )["reporting"]["status"],
            "ready",
        )
        self.assertNotEqual(self.invoke("render", output).returncode, 0)

    def test_invalid_reporting_blocks_publication_without_changing_evidence_status(
        self,
    ):
        bind_plan(self.report, self.assessment)
        self.assessment["reporting"]["routine"] = []
        for action in ("validate", "render"):
            output = self.root / "invalid" if action == "render" else None
            completed = self.invoke(action, output)
            self.assertNotEqual(completed.returncode, 0)
            result = json.loads(completed.stdout)
            self.assertEqual(result["validation_status"], "PASS")
            self.assertEqual(result["reporting"]["status"], "invalid")
            self.assertTrue(result["delivery_summary"]["review_complete"])
            if output is not None:
                self.assertFalse(output.exists())

    def test_routine_render_has_no_dangling_detail_file(self):
        bind_plan(self.report, self.assessment)
        output = self.root / "routine"
        completed = self.invoke("render", output)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse((output / "report-details.md").exists())
        self.assertNotIn("report-details.md", (output / "user-advice.md").read_text())
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "PASS",
        )


if __name__ == "__main__":
    unittest.main()
