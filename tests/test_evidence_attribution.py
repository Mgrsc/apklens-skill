import copy
import hashlib
import json
import struct
import tempfile
import threading
import unittest
import zlib
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from support import make_apk, make_dex
from test_analysis_quality import application, report_for

from scripts.static_analysis.assessment import (
    evidence_inventory,
    prepare_assessment,
    validate_assessment,
    validate_claim,
)
from scripts.static_analysis.binary import dex_index
from scripts.static_analysis.common import (
    Budget,
    Limits,
    aggregate_status,
    snapshot_file,
)
from scripts.static_analysis.endpoints import EndpointCollector
from scripts.static_analysis.engine import (
    analyze_artifact,
    build_findings,
    merge_records,
)
from scripts.static_analysis.facts import application_facts
from scripts.static_analysis.reports import export_reports, summary
from scripts.static_analysis.rules import (
    capabilities,
    sdk_domain_matches,
    sdk_matches,
    signal_decisions,
)
from scripts.static_analysis.storage import APP_SECTIONS, AnalysisStore


class EvidenceAttributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.limits = Limits(max_evidence=1)

    def endpoints(self, value, entry="classes.dex", references=None):
        collector = EndpointCollector(self.limits)
        collector.add_text(
            value,
            {"artifact": "fixture", "entry": entry, "kind": "dex_string"},
            references,
        )
        return collector.results()

    def evidence_records(self):
        return (
            {
                "id": "shared",
                "evidence_level": "E1",
                "evidence": [{"id": "weak", "kind": "dex_string"}],
            },
            {
                "id": "shared",
                "evidence_level": "E2",
                "evidence": [{"id": "strong", "kind": "dex_string_reference"}],
            },
        )

    def test_endpoint_cap_retains_instruction_witness(self):
        record = self.endpoints(
            "https://service.example.test/collect",
            references=[{"method": "Lfixture/Main;->run()V", "instruction_offset": 0}],
        )[0]
        self.assertEqual(record["evidence_level"], "E2")
        self.assertEqual(len(record["evidence"]), 1)
        self.assertEqual(record["evidence"][0]["kind"], "dex_string_reference")

    def test_memory_merge_retains_strongest_in_both_orders(self):
        weak, strong = self.evidence_records()
        for values in ((weak, strong), (strong, weak), (weak, strong, strong)):
            with self.subTest(order=[item["evidence_level"] for item in values]):
                merged, truncated = merge_records(values, self.limits)
                self.assertTrue(truncated)
                self.assertEqual(merged[0]["evidence"][0]["id"], "strong")
                self.assertEqual(weak["evidence"][0]["id"], "weak")

    def test_sqlite_merge_keeps_artifact_fact_immutable(self):
        weak, strong = self.evidence_records()
        with closing(AnalysisStore(self.root / "facts.sqlite3")) as store:
            app = application()
            store.save_artifact(
                "fixture", {"stages": [], "endpoints": [copy.deepcopy(weak)]}
            )
            store.begin_app(app)
            source = store.records("artifact", "fixture", "endpoints")
            store.merge(app["id"], "endpoints", source, self.limits)
            store.merge(app["id"], "endpoints", [copy.deepcopy(strong)], self.limits)
            result = next(iter(store.records("app", app["id"], "endpoints")))
            self.assertEqual(result["evidence"][0]["id"], "strong")
            self.assertEqual(next(iter(source))["evidence"][0]["id"], "weak")

    def test_finding_sample_retains_highest_event_witness(self):
        app = application()
        app["findings"] = []
        app["signals"] = [
            {
                "id": "field-" + str(index),
                "type": "diagnostic_field",
                "evidence_level": "E1",
                "evidence": [{"id": "weak-" + str(index), "kind": "dex_string"}],
            }
            for index in range(20)
        ] + [
            {
                "id": "event",
                "type": "telemetry_event",
                "evidence_level": "E2",
                "evidence": [{"id": "strong", "kind": "dex_invocation"}],
            }
        ]
        build_findings(app)
        finding = next(
            item
            for item in app["findings"]
            if item["type"] == "telemetry_implementation_candidate"
        )
        self.assertEqual(finding["evidence_level"], "E2")
        self.assertIn("strong", finding["evidence_ids"])

    def test_weak_position_does_not_cover_strong_parent_category(self):
        app = application()
        weak, strong = self.evidence_records()
        endpoint = {**strong, "evidence": weak["evidence"] + strong["evidence"]}
        app["endpoints"] = [endpoint]
        app["findings"] = [
            {
                "id": "candidate",
                "type": "sdk_endpoint_candidate",
                "evidence_level": "E2",
                "evidence_ids": ["weak", "strong"],
            }
        ]
        claim = {
            "id": "clue",
            "type": "static_clue",
            "text": "A string exists; its use remains unknown",
            "evidence_ids": ["weak"],
        }
        self.assertEqual(validate_claim(app, claim), [])
        inventory = evidence_inventory(app, [claim])
        self.assertTrue(all(not item["covered"] for item in inventory))
        claim["evidence_ids"] = ["strong"]
        self.assertTrue(
            all(item["covered"] for item in evidence_inventory(app, [claim]))
        )

    def test_legacy_finding_without_instruction_witness_cannot_cover_e2(self):
        app = application()
        weak, _ = self.evidence_records()
        app["endpoints"] = [weak]
        app["findings"] = [
            {
                "id": "unsupported",
                "type": "sdk_endpoint_candidate",
                "evidence_level": "E2",
                "evidence_ids": ["weak"],
            }
        ]
        claim = {
            "id": "clue",
            "type": "static_clue",
            "text": "Only a string is supported",
            "finding_ids": ["unsupported"],
        }
        self.assertEqual(validate_claim(app, claim), [])
        group = next(
            item
            for item in evidence_inventory(app, [claim])
            if item["section"] == "findings"
        )
        self.assertFalse(group["covered"])

    def test_ui_event_face_listener_and_sensor_parameter_are_neutral(self):
        cases = (
            (
                "telemetry_event",
                "Landroidx/compose/ui/platform/AndroidComposeViewAccessibilityDelegateCompat;->sendEvent(Landroid/view/accessibility/AccessibilityEvent;)Z",
            ),
            (
                "speech_recognition",
                "Lfixture/FaceRecognition;-><init>(Lfixture/OnFaceRecognitionListener;)V",
            ),
            (
                "sensor_api",
                "Lfixture/Container;-><init>(Landroid/hardware/SensorManager;)V",
            ),
            (
                "sensor_api",
                "Landroid/hardware/SensorManager;->unregisterListener(Landroid/hardware/SensorEventListener;)V",
            ),
        )
        for category, signature in cases:
            with self.subTest(signature=signature):
                self.assertNotIn(category, signal_decisions(signature, "E2"))

    def test_known_event_speech_and_sensor_calls_are_retained(self):
        cases = (
            (
                "telemetry_event",
                "Lcom/google/firebase/analytics/FirebaseAnalytics;->logEvent(Ljava/lang/String;Landroid/os/Bundle;)V",
            ),
            (
                "speech_recognition",
                "Landroid/speech/SpeechRecognizer;->startListening(Landroid/content/Intent;)V",
            ),
            (
                "sensor_api",
                "Landroid/hardware/SensorManager;->registerListener(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;I)Z",
            ),
        )
        for category, signature in cases:
            with self.subTest(signature=signature):
                self.assertIn(category, signal_decisions(signature, "E2"))

    def test_snapshot_permissions_do_not_become_manifest_declarations(self):
        for granted in (True, False):
            permission = {
                "name": "android.permission.RECORD_AUDIO",
                "declaration": "snapshot_only",
                "granted": granted,
                "grant_source": "runtime",
                "artifacts": [],
            }
            self.assertEqual(capabilities([permission], []), [])
            permission["declaration"] = "uses-permission"
            self.assertEqual(capabilities([permission], [])[0]["type"], "microphone")

    def test_declaration_findings_preserve_only_manifest_sources(self):
        for permission in (
            "QUERY_ALL_PACKAGES",
            "READ_PHONE_STATE",
            "FOREGROUND_SERVICE_MEDIA_PROJECTION",
            "RECORD_AUDIO",
        ):
            with self.subTest(permission=permission):
                app = application()
                app["findings"] = []
                app["signals"] = []
                app["artifacts"].append({"sha256": "b" * 64})
                app["permissions"] = [
                    {
                        "name": "android.permission." + permission,
                        "declaration": "uses-permission",
                        "grant_source": "runtime",
                        "granted": False,
                        "artifacts": ["a" * 64],
                    },
                    {
                        "name": "android.permission." + permission,
                        "declaration": "snapshot_only",
                        "grant_source": "shared_uid",
                        "granted": True,
                        "artifacts": ["b" * 64],
                    },
                ]
                app["capabilities"] = capabilities(app["permissions"], [])
                build_findings(app)
                evidence = app["findings"][0]["evidence"]
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0]["kind"], "manifest_permission")
                self.assertEqual(evidence[0]["artifacts"], ["a" * 64])
                self.assertEqual(evidence[0]["declaration"], "uses-permission")
                self.assertEqual(evidence[0]["grant_source"], "runtime")
                claim = {
                    "id": "declaration",
                    "type": "declaration",
                    "text": "The base manifest declares the permission",
                    "finding_ids": [app["findings"][0]["id"]],
                    "evidence_ids": [evidence[0]["id"]],
                }
                self.assertEqual(validate_claim(app, claim), [])
                with closing(
                    AnalysisStore(self.root / (permission + ".sqlite3"))
                ) as store:
                    stored = copy.deepcopy(app)
                    store.begin_app(stored)
                    for section in APP_SECTIONS:
                        stored[section].extend(app[section])
                    store.save_app(stored)
                    self.assertEqual(validate_claim(stored, claim), [])
                    self.assertEqual(
                        next(iter(stored["findings"]))["evidence"], evidence
                    )

    def test_legacy_declaration_references_reject_snapshot_and_mixed_artifacts(self):
        app = application()
        app["artifacts"].append({"sha256": "b" * 64})
        permission = "android.permission.RECORD_AUDIO"
        app["permissions"] = [
            {
                "name": permission,
                "declaration": "uses-permission",
                "artifacts": ["a" * 64],
            }
        ]
        for source, artifacts in (
            ("snapshot_only", ["a" * 64]),
            (None, ["b" * 64]),
            (None, ["a" * 64, "b" * 64]),
        ):
            with self.subTest(source=source, artifacts=artifacts):
                evidence = {
                    "id": "legacy",
                    "kind": "manifest_or_snapshot_permission",
                    "excerpt": permission,
                    "artifacts": artifacts,
                }
                if source:
                    evidence["declaration"] = source
                app["findings"] = [
                    {
                        "id": "legacy-finding",
                        "type": "privacy_capability_candidate",
                        "evidence_level": "E0",
                        "evidence": [evidence],
                        "evidence_ids": ["legacy"],
                    }
                ]
                for references in (
                    {"evidence_ids": ["legacy"]},
                    {"finding_ids": ["legacy-finding"]},
                ):
                    claim = {
                        "id": "declaration",
                        "type": "declaration",
                        "text": "A manifest declaration exists",
                        **references,
                    }
                    self.assertTrue(validate_claim(app, claim))
        app["findings"][0]["evidence"][0]["artifacts"] = ["a" * 64]
        self.assertEqual(validate_claim(app, claim), [])
        app["permissions"][0]["declaration"] = "snapshot_only"
        self.assertTrue(validate_claim(app, claim))

    def test_duplicate_structure_records_do_not_gain_evidence_fields(self):
        record = {"id": "method", "signature": "Lfixture/Main;->run()V"}
        self.assertEqual(
            merge_records([record, record], self.limits), ([record], False)
        )
        with closing(AnalysisStore(self.root / "structure.sqlite3")) as store:
            app = application()
            store.begin_app(app)
            store.merge(app["id"], "methods", [record, record], self.limits)
            self.assertEqual(list(app["methods"]), [record])

    def malformed_class_definitions(self, type_index):
        data = bytearray(make_dex())
        offset = struct.unpack_from("<I", data, 100)[0]
        definitions = data[offset : offset + 32] * 2
        struct.pack_into("<I", definitions, 32, type_index)
        struct.pack_into("<II", data, 96, 2, len(data))
        data.extend(definitions)
        struct.pack_into("<I", data, 32, len(data))
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
        return bytes(data)

    def test_invalid_class_definitions_preserve_independent_dex_facts(self):
        for type_index in (0, 999):
            for inspect_code in (False, True):
                with self.subTest(type_index=type_index, inspect_code=inspect_code):
                    index = dex_index(
                        self.malformed_class_definitions(type_index),
                        Limits(),
                        Budget(Limits(), threading.Event()),
                        inspect_code,
                    )
                    self.assertEqual(index["defined_types"], {0: 0})
                    self.assertEqual(len(index["methods"]), 2)
                    self.assertFalse(index["definition_inventory_complete"])
                    self.assertTrue(index["structure_gaps"])
                    if inspect_code:
                        self.assertEqual(index["scanned_methods"], 1)
                        self.assertTrue(index["calls"])
                        self.assertFalse(index["reference_scan_complete"])
                    records = sdk_matches(
                        index["types"],
                        [],
                        "fixture",
                        "classes.dex",
                        defined_types=index["defined_types"],
                    )
                    self.assertIn(
                        "Firebase Analytics", {item["name"] for item in records}
                    )

    def test_invalid_class_definitions_remain_partial_in_artifact_analysis(self):
        for mode in ("quick", "standard"):
            for type_index in (0, 999):
                with self.subTest(mode=mode, type_index=type_index):
                    directory = self.root / (mode + str(type_index))
                    directory.mkdir()
                    apk = make_apk(
                        directory / "input.apk",
                        entries={
                            "classes.dex": self.malformed_class_definitions(type_index)
                        },
                    )
                    artifact = snapshot_file(
                        apk, directory / "artifacts", Limits(), threading.Event()
                    )
                    result = analyze_artifact(
                        artifact, Limits(), mode, threading.Event()
                    )
                    self.assertEqual(aggregate_status(result["stages"]), "PARTIAL")
                    self.assertIn(
                        "Firebase Analytics", {item["name"] for item in result["sdks"]}
                    )
                    structure = next(
                        item
                        for item in result["stages"]
                        if item["stage"] == "dex_structure_index"
                    )
                    self.assertEqual(structure["status"], "PARTIAL")

    def test_failed_delivery_counts_only_valid_claims_and_recommendations(self):
        app = application()
        report = report_for([app])
        assessment = prepare_assessment(report)
        row = assessment["applications"][0]
        row["state"] = "reviewed"
        row["reason"] = "The available scope was assessed"
        row["claims"] = [
            {
                "id": "invalid",
                "type": "declaration",
                "text": "No declaration evidence is cited",
            }
        ]
        recommendation = {
            "action": "retain_restrict",
            "conditions": ["If the feature is unused"],
            "claim_ids": ["invalid"],
            "impact": "Access changes",
            "verification": "Check the feature",
            "recovery": "Restore access",
        }
        row["recommendations"] = [recommendation, {"action": "invalid"}]
        result = validate_assessment(report, assessment)
        self.assertEqual(result["validation_status"], "FAILED")
        self.assertEqual(result["delivery_summary"]["claim_count"], 0)
        self.assertEqual(result["delivery_summary"]["recommendation_count"], 0)
        row["claims"] = [
            {
                "id": "valid",
                "type": "direct_call",
                "text": "A direct call exists",
                "evidence_ids": [app["signals"][0]["evidence"][0]["id"]],
            }
        ]
        recommendation["claim_ids"] = ["valid"]
        result = validate_assessment(report, assessment)
        self.assertEqual(result["delivery_summary"]["claim_count"], 1)
        self.assertEqual(result["delivery_summary"]["recommendation_count"], 1)
        row["state"] = "pending"
        self.assertEqual(
            validate_assessment(report, assessment)["delivery_summary"][
                "recommendation_count"
            ],
            0,
        )
        row["state"] = "unknown"
        self.assertEqual(
            validate_assessment(report, assessment)["delivery_summary"][
                "recommendation_count"
            ],
            0,
        )

    def test_foundation_components_do_not_imply_social_or_analytics(self):
        records = sdk_matches(
            [
                "Lcom/facebook/imagepipeline/core/ImagePipeline;",
                "Lcom/facebook/soloader/SoLoader;",
                "Lcom/facebook/react/ReactActivity;",
                "Lcom/alibaba/fastjson/JSON;",
                "Lcom/tencent/mmkv/MMKV;",
                "Lcom/bytedance/shadowhook/ShadowHook;",
            ],
            [],
            "fixture",
            "classes.dex",
        )
        self.assertEqual(
            {item["name"] for item in records},
            {"Fresco", "SoLoader", "React Native", "fastjson", "MMKV", "ShadowHook"},
        )
        self.assertTrue(all(item["purpose"] == "foundation" for item in records))

    def test_vendor_parent_does_not_duplicate_specific_component(self):
        records = sdk_matches(
            [
                "Lcom/tencent/bugly/BuglyStrategy;",
                "Lcom/bytedance/sdk/openadsdk/TTAdSdk;",
                "Lcom/facebook/FacebookSdk;",
                "Lcom/facebook/appevents/AppEventsLogger;",
                "Lcom/facebook/common/Unresolved;",
            ],
            [],
            "fixture",
            "classes.dex",
        )
        names = {item["name"] for item in records}
        self.assertTrue(
            {"Bugly", "Pangle", "Facebook Core", "Facebook App Events"} <= names
        )
        self.assertNotIn("Tencent", names)
        self.assertNotIn("ByteDance", names)
        unknown = next(item for item in records if item["name"] == "Meta")
        self.assertEqual(unknown["record_kind"], "vendor_reference")
        self.assertEqual(unknown["purpose"], "sdk")

    def test_documentation_and_policy_domains_are_not_telemetry_services(self):
        for value, entry in (
            ("https://manual.sensorsdata.cn/sa/latest/flutter.html", "classes.dex"),
            ("https://docs.sentry.io/platforms/android/crash/", "classes.dex"),
            (
                "https://appsflyer.com",
                "assets/privacy_sandbox_attestations/privacy-sandbox-attestations.dat",
            ),
        ):
            with self.subTest(value=value):
                app = application()
                app["findings"] = []
                app["signals"] = []
                app["capabilities"] = []
                app["endpoints"] = self.endpoints(value, entry)
                build_findings(app)
                self.assertEqual(app["findings"], [])
                self.assertNotIn(
                    "sdk_telemetry_domain_candidate", app["endpoints"][0]["tags"]
                )

    def test_service_domain_and_unknown_custom_host_remain_candidates(self):
        for value in (
            "https://errors.sentry.io/api/collect",
            "https://docs.custom.example.test/collect",
        ):
            app = application()
            app["findings"] = []
            app["signals"] = []
            app["capabilities"] = []
            app["endpoints"] = self.endpoints(value)
            build_findings(app)
            self.assertTrue(app["findings"])

    def test_domain_records_do_not_multiply_with_dex_count(self):
        cancel = threading.Event()
        limits = Limits()
        apk = make_apk(
            self.root / "multidex.apk",
            entries={
                "classes.dex": make_dex(url="https://events.sentry.io/api/collect"),
                "classes2.dex": make_dex(url="https://events.sentry.io/api/collect"),
                "classes3.dex": make_dex(url="https://events.sentry.io/api/collect"),
            },
        )
        artifact = snapshot_file(apk, self.root / "artifacts", limits, cancel)
        result = analyze_artifact(artifact, limits, "standard", cancel)
        matches = [item for item in result["sdks"] if item["name"] == "Sentry"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["record_kind"], "service_reference")

    def test_dex_definition_inventory_is_available_in_quick_mode(self):
        limits = Limits()
        for inspect_code in (False, True):
            index = dex_index(
                make_dex(), limits, Budget(limits, threading.Event()), inspect_code
            )
            self.assertEqual(index["defined_types"], {0: 0})
            records = sdk_matches(
                ["Lcom/facebook/imagepipeline/core/ImagePipeline;"],
                [],
                "fixture",
                "classes.dex",
                defined_types=index["defined_types"],
            )
            self.assertEqual(records[0]["evidence"][0]["kind"], "dex_class_definition")

    def test_empty_ledger_exposes_deterministic_delivery_state(self):
        report = report_for([application()])
        report["run"]["stop_reason"] = "analysis_timeout"
        assessment = prepare_assessment(report)
        result = validate_assessment(report, assessment)
        delivery = result["delivery_summary"]
        self.assertEqual(delivery["claim_count"], 0)
        self.assertEqual(delivery["recommendation_count"], 0)
        self.assertEqual(delivery["review_counts"]["pending"], 1)
        self.assertEqual(delivery["stop_reason"], "analysis_timeout")
        self.assertFalse(delivery["review_complete"])
        json.dumps(delivery)

    def test_unobserved_rules_have_synthetic_positive_controls(self):
        cases = {
            "Adjust": "Lcom/adjust/sdk/Adjust;",
            "Sogou": "Lcom/sogou/Fixture;",
            "iFlytek": "Lcom/iflytek/Fixture;",
            "Amplitude": "Lcom/amplitude/api/AmplitudeClient;",
            "OneSignal": "Lcom/onesignal/OneSignal;",
            "GrowingIO": "Lcom/growingio/android/sdk/collection/GrowingIO;",
            "JPush": "Lcn/jpush/android/api/JPushInterface;",
        }
        for name, descriptor in cases.items():
            with self.subTest(name=name):
                records = sdk_matches([descriptor], [], "fixture", "classes.dex")
                self.assertEqual([item["name"] for item in records], [name])
                self.assertEqual(records[0]["evidence_level"], "E1")
                self.assertEqual(
                    records[0]["evidence"][0]["kind"], "dex_type_reference"
                )

    def test_component_counts_ignore_dex_and_vendor_repetition(self):
        app = application()
        for entry in ("classes.dex", "classes2.dex"):
            app["sdks"].extend(
                sdk_matches(["Lcom/tencent/mmkv/MMKV;"], [], "fixture", entry)
            )
        facts = application_facts(app, {})["sdks"]
        self.assertEqual(facts["records"], 2)
        self.assertEqual(facts["component_candidates"], ["MMKV"])
        self.assertEqual(facts["vendor_references"], [])
        total = summary(report_for([app]))["facts"]["sdks"]
        self.assertEqual(total["distinct_components"], 1)
        self.assertEqual(total["component_application_groups"], {"MMKV": 1})
        app["sdks"].append({"id": "legacy", "name": "Tencent", "evidence": []})
        self.assertIsNone(application_facts(app, {})["sdks"]["component_candidates"])

    def test_mixed_roles_survive_endpoint_merge(self):
        value = "https://appsflyer.com/collect"
        policy = self.endpoints(value, "assets/privacy_sandbox_attestations/list.dat")[
            0
        ]
        service = self.endpoints(value, "classes.dex")[0]
        for records in ((policy, service), (service, policy)):
            merged, _ = merge_records(records, self.limits)
            app = application()
            app["signals"] = []
            app["findings"] = []
            app["endpoints"] = merged
            build_findings(app)
            self.assertIn("unknown", app["endpoints"][0]["roles"])
            self.assertTrue(app["findings"])

    def test_domain_evidence_budget_does_not_hide_later_service_role(self):
        records = []
        for index in range(3):
            records.extend(self.endpoints(f"https://docs.sentry.io/help/{index}"))
        records.extend(self.endpoints("https://errors.sentry.io/api/collect"))
        selected = sdk_domain_matches(records)["Sentry"]
        self.assertEqual(len(selected), 3)
        self.assertIn("errors.sentry.io", {item["host"] for item in selected})

    def test_documentation_export_is_filtered_without_deleting_addresses(self):
        app = application()
        app["findings"] = []
        app["signals"] = []
        app["endpoints"] = self.endpoints("https://docs.sentry.io/crash/")
        build_findings(app)
        output = self.root / "export"
        export_reports(report_for([app]), output)
        self.assertIn("docs.sentry.io", (output / "domains.txt").read_text())
        self.assertEqual((output / "telemetry-domains.txt").read_text(), "")

    def test_definition_witness_is_retained_with_single_evidence_budget(self):
        records = sdk_matches(
            ["Lcom/tencent/mmkv/Reference;", "Lcom/tencent/mmkv/MMKV;"],
            [],
            "fixture",
            "classes.dex",
            defined_types={1: 0},
            max_evidence=1,
        )
        self.assertEqual(records[0]["evidence"][0]["kind"], "dex_class_definition")
        self.assertTrue(records[0]["evidence_truncated"])

    def test_sdk_namespace_index_preserves_first_definition_and_reference(self):
        types = [
            "Lcom/tencent/mmkv/Reference;",
            "Lcom/tencent/mmkv/Second;",
            "Lcom/tencent/mmkv/MMKV;",
            "Lcom/tencent/Unknown;",
            "Lcom/tencent/mmkv/Later;",
        ]
        records = sdk_matches(
            types, [], "fixture", "classes.dex", defined_types={2: 0, 4: 1}
        )
        self.assertEqual([item["name"] for item in records], ["Tencent", "MMKV"])
        self.assertEqual(
            [item["type_index"] for item in records[1]["evidence"]], [0, 2]
        )
        self.assertEqual(
            [item["kind"] for item in records[1]["evidence"]],
            ["dex_type_reference", "dex_class_definition"],
        )
        self.assertEqual(records[1]["evidence"][1]["class_def_index"], 0)
        self.assertEqual(records[0]["evidence"][0]["type_index"], 3)

    def test_endpoint_projection_writes_only_role_or_tag_changes(self):
        app = application()
        app["findings"] = []
        app["signals"] = []
        endpoints = self.endpoints("https://errors.sentry.io/collect") + self.endpoints(
            "https://docs.sentry.io/help"
        )
        with closing(AnalysisStore(self.root / "endpoint-writes.sqlite3")) as store:
            store.begin_app(app)
            store.merge(app["id"], "endpoints", endpoints, self.limits)
            with patch.object(
                store, "update_record", wraps=store.update_record
            ) as update:
                build_findings(app, store)
                self.assertEqual(update.call_count, 1)
            app["findings"] = []
            with patch.object(
                store, "update_record", wraps=store.update_record
            ) as update:
                build_findings(app, store)
                self.assertEqual(update.call_count, 0, str(update.call_args_list))

    def test_sqlite_and_memory_exports_share_classification_and_roles(self):
        app = application()
        app["findings"] = []
        app["signals"] = []
        app["endpoints"] = self.endpoints("https://docs.sentry.io/crash/")
        app["endpoints"] += self.endpoints("https://errors.sentry.io/api/collect")
        app["sdks"] = sdk_matches(
            ["Lcom/tencent/mmkv/MMKV;", "Lcom/facebook/common/Unknown;"],
            app["endpoints"],
            "fixture",
            "classes.dex",
        )
        build_findings(app)
        report = report_for([app])
        memory_output = self.root / "memory"
        export_reports(report, memory_output, write_analysis=False)
        stored_app = copy.deepcopy(app)
        with closing(AnalysisStore(self.root / "projection.sqlite3")) as store:
            store.begin_app(stored_app)
            for section in APP_SECTIONS:
                stored_app[section].extend(app[section])
            store.save_app(stored_app)
            store.save_report(report)
            sqlite_output = self.root / "sqlite"
            export_reports(store.report(), sqlite_output, write_analysis=False)
            for filename in (
                "domains.txt",
                "telemetry-domains.txt",
                "summary.json",
                "report.md",
            ):
                self.assertEqual(
                    (sqlite_output / filename).read_bytes(),
                    (memory_output / filename).read_bytes(),
                )
        self.assertEqual(
            (sqlite_output / "telemetry-domains.txt").read_text(),
            "errors.sentry.io\n",
        )
        rendered = (sqlite_output / "report.md").read_text()
        self.assertIn("| component |", rendered)
        self.assertIn("| vendor_reference |", rendered)
        self.assertIn("| service_reference |", rendered)


if __name__ == "__main__":
    unittest.main()
