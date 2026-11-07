import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.static_analysis.assessment import (
    prepare_assessment,
    render_assessment,
    validate_assessment,
)
from scripts.static_analysis.common import Limits, stage
from scripts.static_analysis.reports import (
    close_report,
    load_report,
    markdown,
    query,
    summary,
)
from scripts.static_analysis.storage import (
    APP_SECTIONS,
    EVIDENCE_SECTIONS,
    AnalysisStore,
    Apps,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = "a" * 64


def application(package="com.example.target", artifacts=True):
    evidence = {
        "id": package + "-evidence",
        "artifact": ARTIFACT,
        "entry": "classes.dex",
        "method": "Lsample/Main;->run()V",
        "instruction_offset": 0,
        "kind": "dex_invocation",
        "excerpt": "Landroid/content/pm/PackageManager;->getInstalledApplications(I)Ljava/util/List;",
    }
    return {
        "id": package,
        "package": package,
        "version_code": "1",
        "user": 0,
        "status": "PARTIAL",
        "artifacts": [{"sha256": ARTIFACT}] if artifacts else [],
        "manifests": [],
        "methods": [],
        "fields": [],
        "permissions": [],
        "capabilities": [],
        "endpoints": [],
        "sdks": [],
        "signals": [
            {
                "id": package + "-signal",
                "type": "installed_apps_api",
                "evidence_level": "E2",
                "evidence": [evidence],
            }
        ]
        if artifacts
        else [],
        "findings": [
            {
                "id": package + "-finding",
                "type": "privacy_capability_candidate",
                "evidence_level": "E2",
                "evidence_ids": [evidence["id"]],
            }
        ]
        if artifacts
        else [],
        "coverage": [{**stage("dex_references", "PARTIAL"), "artifact": ARTIFACT}]
        if artifacts
        else [],
        "priority": {"score": 1, "reasons": ["installed_apps_api"]},
        "recommendations": [],
        "installation": None,
    }


def report_for(apps):
    return {
        "schema_version": 1,
        "engine_version": "1.2.0",
        "run": {"id": "quality-test", "status": "PARTIAL", "mode": "standard"},
        "stages": [],
        "apps": apps,
        "artifacts": [{"sha256": ARTIFACT}],
        "totals": {
            "apps": len(apps),
            "endpoints": sum(len(app["endpoints"]) for app in apps),
        },
        "limitations": ["Runtime behavior is unverified"],
    }


class AnalysisQualityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def persist(self, report):
        store = AnalysisStore(self.root / "analysis.sqlite3")
        self.addCleanup(store.close)
        for value in report["apps"]:
            app = copy.deepcopy(value)
            sections = {section: app[section] for section in APP_SECTIONS}
            store.begin_app(app)
            for section, records in sections.items():
                if section in EVIDENCE_SECTIONS and section != "findings":
                    store.merge(app["id"], section, records, Limits())
                else:
                    app[section].extend(records)
            store.save_app(app)
        stored = {**report, "apps": Apps(store)}
        store.save_report(stored)
        return store, stored

    def test_scope_and_sdk_units_are_not_added_or_confused(self):
        first, second = application(), application("com.example.second")
        for app in (first, second):
            app["sdks"] = [
                {"id": app["id"] + str(index), "name": "ExampleSDK", "evidence": []}
                for index in range(2)
            ]
            app["endpoints"] = [
                {
                    "id": app["id"],
                    "host": None,
                    "tags": [],
                    "kind": "domain",
                    "value": "example.test",
                    "evidence_level": "E1",
                    "evidence": [],
                }
            ]
        report = report_for([first, second])
        report["artifacts"][0]["endpoints"] = ["unused"] * 99
        facts = summary(report)["facts"]
        self.assertEqual(facts["endpoints"]["records"], 2)
        self.assertEqual(facts["sdks"]["records"], 4)
        self.assertEqual(facts["sdks"]["distinct_names"], 1)
        self.assertEqual(
            facts["sdks"]["by_name"]["ExampleSDK"]["application_groups"], 2
        )
        self.assertEqual(facts["artifacts"]["unique"], 1)

    def test_permissions_and_unavailable_apks_have_separate_denominators(self):
        app = application()
        app["permissions"] = [
            {
                "name": "permission.A",
                "declaration": "uses-permission",
                "grant_source": "requested_permissions",
            },
            {
                "name": "permission.B",
                "declaration": "snapshot_only",
                "grant_source": "shared_uid_install_permissions",
            },
        ]
        facts = summary(report_for([app, application("com.example.missing", False)]))[
            "facts"
        ]
        self.assertEqual(facts["applications"]["groups"], 2)
        self.assertEqual(facts["applications"]["with_apk"], 1)
        self.assertEqual(facts["applications"]["without_apk"], 1)
        self.assertEqual(facts["permissions"]["manifest_records"], 1)
        self.assertEqual(facts["permissions"]["snapshot_only_records"], 1)
        self.assertEqual(facts["artifacts"]["status_counts"], {"PARTIAL": 1})

    def test_candidate_outside_top_twenty_is_still_in_assessment(self):
        apps = [application("com.example.app" + str(index)) for index in range(25)]
        report = report_for(apps)
        self.assertEqual(len(summary(report)["apps"]), 20)
        prepared = prepare_assessment(report)
        self.assertEqual(len(prepared["applications"]), 25)
        self.assertTrue(
            all(
                row["context"]["facts"]["review"]["required"]
                for row in prepared["applications"]
            )
        )
        page = query(report, "apps", offset=20, limit=3)
        self.assertTrue(page["has_more"])
        self.assertEqual(page["next_offset"], 23)
        self.assertFalse(query(report, "apps", offset=25)["has_more"])

    def test_markdown_discloses_table_totals_and_missing_code(self):
        text = markdown(
            report_for([application(), application("com.example.missing", False)]),
            limit=1,
        )
        self.assertIn("apps: total=2, shown=1, not_shown=1", text)
        self.assertIn('"without_apk": 1', text)
        self.assertIn("app-scope candidate records only", text)

    def test_old_projection_and_json_sqlite_views_match_without_writes(self):
        report = report_for([application()])
        store, stored = self.persist(report)
        projection = store.metadata("app_view:" + report["apps"][0]["id"])
        projection.pop("facts")
        store.set_metadata("app_view:" + report["apps"][0]["id"], projection)
        store.connection.commit()
        before = store.path.read_bytes()
        opened = load_report(store.path)
        try:
            self.assertEqual(query(opened, "apps"), query(report, "apps"))
            self.assertEqual(summary(opened)["facts"], summary(report)["facts"])
        finally:
            close_report(opened)
        self.assertEqual(store.path.read_bytes(), before)
        self.assertEqual(summary(stored)["facts"], summary(report)["facts"])

    def test_missing_installation_metadata_does_not_claim_user_installation(self):
        app = application()
        app["installation"] = {
            "flags": ["SYSTEM"],
            "is_system": True,
            "stages": [stage("package_permissions", "UNAVAILABLE")],
        }
        facts = summary(report_for([app]))["facts"]
        self.assertEqual(facts["applications"]["classification_unknown"], 1)
        self.assertEqual(facts["applications"]["system"], 0)


class AssessmentValidationTests(unittest.TestCase):
    def setUp(self):
        self.report = report_for(
            [application(), application("com.example.missing", False)]
        )
        self.assessment = prepare_assessment(self.report)

    def reviewed(self):
        row = self.assessment["applications"][0]
        row["state"] = "reviewed"
        row["reason"] = (
            "Available calls and coverage were inspected; runtime remains unknown"
        )
        row["claims"] = [
            {
                "id": "call",
                "type": "direct_call",
                "text": "An installed-app enumeration call exists",
                "finding_ids": ["com.example.target-finding"],
                "evidence_ids": ["com.example.target-evidence"],
            }
        ]
        return row

    def test_preparation_exposes_outstanding_review_even_when_valid(self):
        result = validate_assessment(self.report, self.assessment)
        self.assertEqual(result["validation_status"], "PASS")
        self.assertEqual(result["outstanding_review"], 1)
        self.assertEqual(result["unavailable_code"], 1)
        self.assertEqual(result["review_counts"]["metadata_only"], 1)

    def test_valid_e2_claim_does_not_imply_code_completeness(self):
        self.reviewed()
        result = validate_assessment(self.report, self.assessment)
        self.assertEqual(result["validation_status"], "PASS")
        self.assertEqual(result["analysis_status"], "PARTIAL")
        self.assertEqual(result["unavailable_code"], 1)
        self.assertIn(
            "没有 APK", render_assessment(self.report, self.assessment, "zh-CN")
        )

    def test_omission_duplicates_and_identity_changes_are_rejected(self):
        for operation in ("omit", "duplicate", "version", "facts"):
            with self.subTest(operation=operation):
                value = copy.deepcopy(self.assessment)
                if operation == "omit":
                    value["applications"].pop()
                elif operation == "duplicate":
                    value["applications"].append(value["applications"][0])
                elif operation == "version":
                    value["applications"][0]["identity"]["version_code"] = "2"
                else:
                    value["facts"]["endpoints"]["records"] += 1
                self.assertEqual(
                    validate_assessment(self.report, value)["validation_status"],
                    "FAILED",
                )

    def test_cooccurrence_cannot_be_promoted_to_static_or_runtime_path(self):
        row = self.reviewed()
        for kind in ("static_path", "observed_upload"):
            row["claims"][0]["type"] = kind
            row["claims"][0]["limitations"] = "Runtime is unknown"
            self.assertEqual(
                validate_assessment(self.report, self.assessment)["validation_status"],
                "FAILED",
            )

    def test_cross_application_evidence_is_rejected(self):
        self.reviewed()["claims"][0]["evidence_ids"] = ["com.example.other-evidence"]
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "FAILED",
        )

    def test_finding_alone_does_not_establish_instruction_reference(self):
        self.reviewed()["claims"][0]["evidence_ids"] = []
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "FAILED",
        )

    def test_malformed_assessments_return_validation_errors(self):
        row = self.reviewed()
        row["recommendations"] = [
            {
                "action": "defer",
                "conditions": ["Pending checks"],
                "claim_ids": ["call"],
                "impact": "Unknown",
                "verification": "Inspect dependencies",
                "recovery": "Unknown",
                "prerequisites": [],
            }
        ]
        mutations = (
            lambda value: value.update(producer=[]),
            lambda value: value.update(applications={}),
            lambda value: value["applications"][0].update(state=[]),
            lambda value: value["applications"][0].pop("reason"),
            lambda value: value["applications"][0].pop("claims"),
            lambda value: value["applications"][0]["claims"][0].update(type=[]),
            lambda value: value["applications"][0]["claims"][0].update(
                evidence_ids=[{}]
            ),
            lambda value: value["applications"][0]["recommendations"][0].update(
                action={}
            ),
            lambda value: value["applications"][0]["recommendations"][0].update(
                claim_ids=[[]]
            ),
            lambda value: value["applications"][0]["recommendations"][0].update(
                prerequisites=[
                    {"type": [], "status": "verified", "basis": "Invalid type"}
                ]
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(self.assessment)
                mutation(value)
                self.assertEqual(
                    validate_assessment(self.report, value)["validation_status"],
                    "FAILED",
                )

    def test_rendered_identity_and_text_cannot_inject_markdown(self):
        injected = "![remote](https://example.test/tracker)\n<script>unsafe</script>`"
        self.report["apps"][0]["package"] = injected
        self.assessment = prepare_assessment(self.report)
        self.reviewed()["reason"] = injected
        text = render_assessment(self.report, self.assessment)
        self.assertNotIn("![remote]", text)
        self.assertNotIn("<script>", text)
        self.assertNotIn("https://example.test", text)

    def test_modeled_path_requires_its_own_finding_and_limitations(self):
        app = self.report["apps"][0]
        app["findings"].append(
            {
                "id": "flow",
                "type": "privacy_transmission_path",
                "evidence_level": "E3",
                "evidence_ids": ["path-step"],
                "evidence": [
                    {"id": "path-step", "artifact": ARTIFACT, "kind": "network_sink"}
                ],
            }
        )
        self.assessment = prepare_assessment(self.report)
        self.reviewed()["claims"] += [
            {
                "id": "path",
                "type": "static_path",
                "text": "A modeled static path exists",
                "finding_ids": ["flow"],
                "evidence_ids": ["path-step"],
                "limitations": "Runtime execution and authorization remain unknown",
            }
        ]
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "PASS",
        )
        self.assessment["applications"][0]["claims"][1]["limitations"] = ""
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "FAILED",
        )

    def test_shared_uid_grant_scope_is_checked(self):
        app = self.report["apps"][0]
        app["permissions"] = [
            {
                "name": "permission.A",
                "declaration": "snapshot_only",
                "granted": True,
                "grant_source": "shared_uid_install_permissions",
            }
        ]
        self.assessment = prepare_assessment(self.report)
        row = self.reviewed()
        row["claims"] += [
            {
                "id": "grant",
                "type": "snapshot_grant",
                "text": "Shared UID grant",
                "permission": "permission.A",
                "granted": True,
                "grant_source": "shared_uid_install_permissions",
                "grant_scope": "app",
            }
        ]
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "FAILED",
        )
        row["claims"][1]["grant_scope"] = "shared_uid"
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "PASS",
        )

    def test_system_disable_without_dependency_evidence_is_deferred(self):
        row = self.reviewed()
        row["recommendations"] = [
            {
                "action": "disable_optional",
                "conditions": ["If unused"],
                "claim_ids": ["call"],
                "impact": "Feature loss",
                "verification": "Check required functions",
                "recovery": "Not verified",
                "prerequisites": [],
            }
        ]
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "FAILED",
        )
        row["recommendations"][0]["action"] = "defer"
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "PASS",
        )

    def test_metadata_only_cannot_be_labelled_code_reviewed(self):
        row = self.assessment["applications"][1]
        row["state"] = "reviewed"
        self.assertEqual(
            validate_assessment(self.report, self.assessment)["validation_status"],
            "FAILED",
        )

    def test_cli_preparation_validation_rendering_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "analysis.json"
            report.write_text(json.dumps(self.report))
            prepared = root / "prepared"
            command = [sys.executable, str(ROOT / "scripts/assess_results.py")]
            first = subprocess.run(
                [*command, "prepare", str(report), "--output", str(prepared)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(json.loads(first.stdout)["outstanding_review"], 1)
            for action in ("validate", "render"):
                options = (
                    ["--output", str(root / "rendered")] if action == "render" else []
                )
                result = subprocess.run(
                    [
                        *command,
                        action,
                        str(report),
                        "--assessment",
                        str(prepared / "assessment.json"),
                        *options,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            original = (prepared / "assessment.json").read_bytes()
            repeated = subprocess.run(
                [*command, "prepare", str(report), "--output", str(prepared)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(repeated.returncode, 1)
            self.assertEqual((prepared / "assessment.json").read_bytes(), original)
            self.assertTrue((root / "rendered" / "user-advice.md").is_file())
