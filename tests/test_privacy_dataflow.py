import json
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from privacy_fixtures import (
    IDENTITY,
    ROOT_METHOD,
    byte_transmission,
    privacy_dex,
    transmission,
)
from support import make_apk

from scripts.static_analysis import dataflow
from scripts.static_analysis.binary import dex_index
from scripts.static_analysis.common import (
    Budget,
    Cancelled,
    Limits,
    MemoryBudgetExceeded,
    snapshot_file,
)
from scripts.static_analysis.engine import analyze_artifact, build_apps, cache_key
from scripts.static_analysis.privacy_models import (
    AUDIO_READS,
    SCREEN_SURFACE,
    SOURCE_METHODS,
)
from scripts.static_analysis.reports import close_report, load_report, query, summary
from scripts.static_analysis.rules import signal_matches
from scripts.static_analysis.storage import AnalysisStore, ArtifactResults

ROOT = Path(__file__).resolve().parents[1]


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()

    def program(self, code=None, definitions=None, **options):
        if definitions is None:
            definitions = [
                {
                    "signature": ROOT_METHOD,
                    "code": code
                    or [
                        ("invoke", IDENTITY, [7], False),
                        ("result", 0),
                        *transmission(),
                        0x0E,
                    ],
                }
            ]
        data = privacy_dex(definitions, **options)
        index = dex_index(data, self.limits, Budget(self.limits))
        self.assertEqual(index["gaps"], [])
        methods = [
            {"id": str(i), "artifact": "artifact", "entry": "classes.dex", **body}
            for i, body in enumerate(index["bodies"])
        ]
        return data, methods

    def flows(self, methods, limits=None):
        return dataflow.analyze_dataflow(methods, limits or self.limits, self.cancel)

    def test_direct_path_has_complete_source_transform_and_sink_evidence(self):
        _, methods = self.program()
        flows, coverage = self.flows(methods)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["evidence_level"], "E3")
        self.assertEqual(flows[0]["data_category"], "device_identifier")
        self.assertEqual(flows[0]["evidence"][0]["kind"], "data_source")
        self.assertEqual(flows[0]["evidence"][-1]["kind"], "network_sink")
        self.assertTrue(all(item["status"] == "COMPLETE" for item in coverage))

    def test_cross_method_argument_path_and_return_path(self):
        helper = "Lsample/Send;->send(Ljava/lang/String;)V"
        getter = "Lsample/Get;->value(Landroid/telephony/TelephonyManager;)Ljava/lang/String;"
        for definitions in (
            [
                {
                    "signature": ROOT_METHOD,
                    "code": [
                        ("invoke", IDENTITY, [7], False),
                        ("result", 0),
                        ("invoke", helper, [0], True),
                        0x0E,
                    ],
                },
                {"signature": helper, "code": [*transmission(7), 0x0E]},
            ],
            [
                {
                    "signature": ROOT_METHOD,
                    "code": [
                        ("invoke", getter, [7], True),
                        ("result", 0),
                        *transmission(),
                        0x0E,
                    ],
                },
                {
                    "signature": getter,
                    "code": [
                        ("invoke", IDENTITY, [7], False),
                        ("result", 0),
                        ("return", 0),
                    ],
                },
            ],
        ):
            with self.subTest(definitions=definitions):
                _, methods = self.program(definitions=definitions)
                flows, _ = self.flows(methods)
                self.assertTrue(flows)
                self.assertTrue(all(item["evidence_level"] == "E4" for item in flows))

    def test_value_overwrite_and_unrelated_request_do_not_create_paths(self):
        for code in (
            [
                ("invoke", IDENTITY, [7], False),
                ("result", 0),
                ("string", 0, "public"),
                *transmission(),
                0x0E,
            ],
            [
                ("invoke", IDENTITY, [7], False),
                ("result", 6),
                ("string", 0, "public"),
                *transmission(),
                0x0E,
            ],
            [
                ("invoke", "Lsample/Fake;->getImei()Ljava/lang/String;", [7], False),
                ("result", 0),
                *transmission(),
                0x0E,
            ],
        ):
            with self.subTest(code=code):
                _, methods = self.program(code=code)
                self.assertEqual(self.flows(methods)[0], [])

    def test_json_fields_preserve_object_identity_and_overwrites(self):
        init = "Lorg/json/JSONObject;-><init>()V"
        put = "Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;"
        text = "Lorg/json/JSONObject;->toString()Ljava/lang/String;"
        for replaced, other in ((False, False), (True, False), (False, True)):
            code = [
                ("invoke", IDENTITY, [7], False),
                ("result", 0),
                ("new", 6, "Lorg/json/JSONObject;"),
                ("invoke", init, [6], False),
                ("string", 1, "iccid"),
                ("invoke", put, [6, 1, 0], False),
            ]
            if replaced:
                code += [("string", 0, "public"), ("invoke", put, [6, 1, 0], False)]
            if other:
                code += [
                    ("new", 6, "Lorg/json/JSONObject;"),
                    ("invoke", init, [6], False),
                ]
            code += [("invoke", text, [6], False), ("result", 0), *transmission(), 0x0E]
            _, methods = self.program(code)
            self.assertEqual(bool(self.flows(methods)[0]), not replaced and not other)

    def test_constant_branch_prunes_unreachable_send(self):
        code = [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            0x1612,
            0x0638,
            3,
            0x0E,
            *transmission(),
            0x0E,
        ]
        _, methods = self.program(code)
        self.assertEqual(self.flows(methods)[0], [])

    def test_unknown_branch_preserves_conditions(self):
        code = [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            0x0638,
            3,
            0x0E,
            *transmission(),
            0x0E,
        ]
        _, methods = self.program(code)
        flows, _ = self.flows(methods)
        self.assertEqual(len(flows), 1)
        self.assertTrue(flows[0]["conditions"])

    def test_same_sink_keeps_distinct_branch_conditions_and_destinations(self):
        send = [
            item
            for item in transmission()
            if not (isinstance(item, tuple) and item[0] == "string")
        ]
        _, methods = self.program(
            [
                ("invoke", IDENTITY, [7], False),
                ("result", 0),
                0x0638,
                5,
                ("string", 2, "https://first.example/register"),
                0x0328,
                ("string", 2, "https://second.example/register"),
                *send,
                0x0E,
            ]
        )
        flows, _ = self.flows(methods)
        self.assertEqual(len(flows), 2)
        self.assertEqual(
            {tuple(item["sink"]["endpoints"]) for item in flows},
            {("https://first.example/register",), ("https://second.example/register",)},
        )
        self.assertEqual(len({tuple(item["conditions"]) for item in flows}), 2)

    def test_encryption_preserves_data_source(self):
        encrypt = "Ljavax/crypto/Cipher;->doFinal([B)[B"
        code = [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            ("invoke", "Ljava/lang/String;->getBytes()[B", [0], False),
            ("result", 0),
            ("invoke", encrypt, [6, 0], False),
            ("result", 0),
            *transmission(),
            0x0E,
        ]
        _, methods = self.program(code)
        flows, _ = self.flows(methods)
        self.assertEqual(len(flows), 1)
        self.assertIn(encrypt, [item["excerpt"] for item in flows[0]["evidence"]])

    def test_unresolved_boundaries_and_budgets_remain_visible(self):
        code = [
            (
                "invoke",
                "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
                [0, 1, 2],
                False,
            ),
            0x0E,
        ]
        _, methods = self.program(code)
        self.assertIn("reflection", json.dumps(self.flows(methods)[1]))
        _, methods = self.program()
        for name, value, reason in (
            ("MAX_APP_STEPS", 1, "step budget"),
            ("MAX_HEAP_OBJECTS", 0, "Object budget"),
            ("MAX_CALL_DEPTH", 0, "depth"),
        ):
            with self.subTest(name=name), patch.object(dataflow, name, value):
                flows, coverage = self.flows(methods)
                self.assertEqual(flows, [])
                self.assertIn(reason, json.dumps(coverage))
                self.assertTrue(all(item["status"] == "PARTIAL" for item in coverage))
        self.assertIn(
            "Evidence budget",
            json.dumps(self.flows(methods, replace(self.limits, max_evidence=1))[1]),
        )
        _, methods = self.program(
            definitions=[
                {
                    "signature": f"Lsample/Main;->run{index}(Landroid/telephony/TelephonyManager;)V",
                    "code": [
                        ("invoke", IDENTITY, [7], False),
                        ("result", 0),
                        *transmission(),
                        0x0E,
                    ],
                }
                for index in range(2)
            ]
        )
        flows, coverage = self.flows(methods, replace(self.limits, max_results=1))
        self.assertEqual(len(flows), 1)
        self.assertIn("result budget", json.dumps(coverage))
        self.assertEqual(coverage[0]["status"], "PARTIAL")

    def test_cancellation_propagates(self):
        _, methods = self.program()
        self.cancel.set()
        with self.assertRaises(Cancelled):
            self.flows(methods)

    def test_timeout_is_partial_and_memory_stop_propagates(self):
        _, methods = self.program()
        flows, coverage = self.flows(methods, replace(self.limits, timeout=0))
        self.assertEqual(flows, [])
        self.assertEqual(coverage[0]["status"], "PARTIAL")
        self.assertIn("time budget", json.dumps(coverage))
        with (
            patch("scripts.static_analysis.common.resident_bytes", return_value=2),
            self.assertRaises(MemoryBudgetExceeded),
        ):
            self.flows(methods, replace(self.limits, memory_bytes=1))

    def test_cancellation_after_last_flow_is_not_reported_complete(self):
        _, methods = self.program()
        original = dataflow.Analyzer.emit

        def cancel_after_emit(analyzer, *args, **kwargs):
            original(analyzer, *args, **kwargs)
            self.cancel.set()

        with (
            patch.object(dataflow.Analyzer, "emit", cancel_after_emit),
            self.assertRaises(Cancelled),
        ):
            self.flows(methods)

    def test_audio_buffer_source_and_start_only_negative(self):
        for read in (False, True):
            code = [
                0x4112,
                ("array", 0, "[B", 1),
                (
                    "invoke",
                    "Landroid/media/AudioRecord;->startRecording()V",
                    [7],
                    False,
                ),
            ]
            if read:
                code += [
                    (
                        "invoke",
                        "Landroid/media/AudioRecord;->read([BII)I",
                        [7, 0, 2, 1],
                        False,
                    )
                ]
            code += [*byte_transmission(), 0x0E]
            _, methods = self.program(
                definitions=[
                    {
                        "signature": "Lsample/Main;->run(Landroid/media/AudioRecord;)V",
                        "code": code,
                    }
                ]
            )
            flows, _ = self.flows(methods)
            self.assertEqual(bool(flows), read)
            if read:
                self.assertEqual(flows[0]["data_category"], "audio_capture")

    def test_screen_surface_recording_file_encoding_and_encryption_path(self):
        code = [
            ("new", 0, "Landroid/media/MediaRecorder;"),
            ("invoke", "Landroid/media/MediaRecorder;-><init>()V", [0], False),
            ("string", 1, "/private/clip.mp4"),
            (
                "invoke",
                "Landroid/media/MediaRecorder;->setOutputFile(Ljava/lang/String;)V",
                [0, 1],
                False,
            ),
            (
                "invoke",
                "Landroid/media/MediaRecorder;->getSurface()Landroid/view/Surface;",
                [0],
                False,
            ),
            ("result", 14),
            0x0808,
            19,
            ("string", 9, "capture"),
            0x0A13,
            720,
            0x0B13,
            1280,
            ("invoke-range", SCREEN_SURFACE, 8, 9, False),
            ("invoke", "Landroid/media/MediaRecorder;->start()V", [0], False),
            ("new", 2, "Ljava/io/FileInputStream;"),
            (
                "invoke",
                "Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V",
                [2, 1],
                False,
            ),
            ("invoke", "Ljava/io/FileInputStream;->readAllBytes()[B", [2], False),
            ("result", 0),
            0x0412,
            ("invoke", "Landroid/util/Base64;->encode([BI)[B", [0, 4], True),
            ("result", 0),
            ("invoke", "Ljavax/crypto/Cipher;->doFinal([B)[B", [6, 0], False),
            ("result", 0),
            *byte_transmission(),
            0x0E,
        ]
        _, methods = self.program(
            definitions=[
                {
                    "signature": "Lsample/Main;->run(Landroid/media/projection/MediaProjection;)V",
                    "registers": 20,
                    "code": code,
                }
            ]
        )
        flows, _ = self.flows(methods)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["data_category"], "screen_capture")
        self.assertIn(
            {"index": 1, "constant": 720}, flows[0]["evidence"][0]["arguments"]
        )
        self.assertIn(
            {"index": 2, "constant": 1280}, flows[0]["evidence"][0]["arguments"]
        )
        self.assertEqual(
            flows[0]["sink"]["endpoints"], ["https://private.example/register"]
        )

    def test_async_callback_and_instance_field_path(self):
        field = "Lsample/Job;->payload:Ljava/lang/String;"
        definitions = [
            {
                "signature": "Lsample/Main;->run(Landroid/telephony/TelephonyManager;Landroid/os/Handler;)V",
                "code": [
                    ("invoke", IDENTITY, [6], False),
                    ("result", 0),
                    ("new", 1, "Lsample/Job;"),
                    ("iput", 0, field, 1),
                    (
                        "invoke",
                        "Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z",
                        [7, 1],
                        False,
                    ),
                    0x0E,
                ],
            },
            {
                "signature": "Lsample/Job;->run()V",
                "access": 1,
                "code": [("iget", 0, field, 7), *transmission(), 0x0E],
            },
        ]
        _, methods = self.program(definitions=definitions, fields=[field])
        flows, _ = self.flows(methods)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["evidence_level"], "E4")
        self.assertIn("Scheduled callback", json.dumps(flows[0]["conditions"]))

    def test_static_field_overwrite_and_unrelated_instance(self):
        field = "Lsample/Box;->payload:Ljava/lang/String;"
        for unrelated, overwrite in ((False, False), (True, False), (False, True)):
            code = [
                ("invoke", IDENTITY, [7], False),
                ("result", 0),
                ("new", 6, "Lsample/Box;"),
                ("iput", 0, field, 6),
            ]
            if unrelated:
                code += [("new", 6, "Lsample/Box;")]
            if overwrite:
                code += [("string", 0, "public"), ("iput", 0, field, 6)]
            code += [("iget", 0, field, 6), *transmission(), 0x0E]
            _, methods = self.program(code=code, fields=[field])
            self.assertEqual(
                bool(self.flows(methods)[0]), not unrelated and not overwrite
            )

    def test_unknown_async_and_native_methods_are_located_gaps(self):
        _, methods = self.program(
            code=[
                (
                    "invoke",
                    "Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z",
                    [0, 1],
                    False,
                ),
                0x0E,
            ]
        )
        self.assertIn("callback target", json.dumps(self.flows(methods)[1]))
        _, methods = self.program(
            definitions=[
                {"signature": "Lsample/Native;->read()V", "access": 0x109, "code": []}
            ]
        )
        _, coverage = self.flows(methods)
        self.assertIn("Lsample/Native;", json.dumps(coverage))
        self.assertIn("Native", json.dumps(coverage))

    def test_unknown_call_does_not_reuse_stale_mutable_object_fields(self):
        field = "Lsample/Box;->payload:Ljava/lang/String;"
        code = [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            ("new", 6, "Lsample/Box;"),
            ("iput", 0, field, 6),
            ("invoke", "Lsample/Unknown;->mutate(Lsample/Box;)V", [6], True),
            ("iget", 0, field, 6),
            *transmission(),
            0x0E,
        ]
        _, methods = self.program(code=code, fields=[field])
        flows, coverage = self.flows(methods)
        self.assertEqual(flows, [])
        self.assertIn("Unmodeled external invocation", json.dumps(coverage))

    def test_serialization_is_a_snapshot_and_does_not_capture_later_mutation(self):
        put = "Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;"
        text = "Lorg/json/JSONObject;->toString()Ljava/lang/String;"
        code = [
            ("new", 6, "Lorg/json/JSONObject;"),
            ("invoke", text, [6], False),
            ("result", 5),
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            ("string", 1, "identifier"),
            ("invoke", put, [6, 1, 0], False),
            ("invoke", "Ljava/lang/String;->getBytes()[B", [5], False),
            ("result", 0),
            *byte_transmission(),
            0x0E,
        ]
        _, methods = self.program(code)
        self.assertEqual(self.flows(methods)[0], [])

    def test_reading_public_json_key_does_not_inherit_another_keys_secret(self):
        code = [
            ("new", 6, "Lorg/json/JSONObject;"),
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            ("string", 1, "secret"),
            (
                "invoke",
                "Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;",
                [6, 1, 0],
                False,
            ),
            ("string", 1, "public"),
            (
                "invoke",
                "Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;",
                [6, 1],
                False,
            ),
            ("result", 0),
            *transmission(),
            0x0E,
        ]
        _, methods = self.program(code)
        self.assertEqual(self.flows(methods)[0], [])

    def test_file_url_is_not_a_network_sink(self):
        code = [("invoke", IDENTITY, [7], False), ("result", 0), *transmission(), 0x0E]
        code = [
            ("string", 2, "file:///private/cache")
            if isinstance(item, tuple) and item[0] == "string" and item[1] == 2
            else item
            for item in code
        ]
        _, methods = self.program(code)
        self.assertEqual(self.flows(methods)[0], [])

    def test_disabled_output_closed_stream_and_empty_slice_do_not_transmit(self):
        from privacy_fixtures import WRITE

        original = [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            *transmission(),
            0x0E,
        ]
        disabled = [
            item
            for item in original
            if not (
                isinstance(item, tuple)
                and item[0] == "invoke"
                and "setDoOutput" in item[1]
            )
        ]
        closed, empty = [], []
        for item in original:
            if isinstance(item, tuple) and item[:2] == ("invoke", WRITE):
                closed.append(
                    ("invoke", "Ljava/io/OutputStream;->close()V", [4], False)
                )
                empty.extend(
                    [
                        0x0612,
                        0x0712,
                        (
                            "invoke",
                            "Ljava/io/OutputStream;->write([BII)V",
                            [4, 5, 6, 7],
                            False,
                        ),
                    ]
                )
            else:
                empty.append(item)
            closed.append(item)
        for code in (disabled, closed, empty):
            with self.subTest(code=code):
                _, methods = self.program(code)
                self.assertEqual(self.flows(methods)[0], [])

    def test_known_list_element_selection_does_not_inherit_other_elements(self):
        for index in (0, 1):
            code = [
                ("invoke", IDENTITY, [7], False),
                ("result", 0),
                ("new", 6, "Ljava/util/ArrayList;"),
                (
                    "invoke",
                    "Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z",
                    [6, 0],
                    False,
                ),
                ("string", 0, "public"),
                (
                    "invoke",
                    "Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z",
                    [6, 0],
                    False,
                ),
                0x0012 | index << 12,
                (
                    "invoke",
                    "Ljava/util/ArrayList;->get(I)Ljava/lang/Object;",
                    [6, 0],
                    False,
                ),
                ("result", 0),
                *transmission(),
                0x0E,
            ]
            _, methods = self.program(code)
            self.assertEqual(bool(self.flows(methods)[0]), index == 0)

    def test_wrapper_and_delegate_share_closed_state(self):
        from privacy_fixtures import WRITE

        for closed_register, output_register in ((4, 6), (6, 4), (6, 6)):
            code = []
            for item in [
                ("invoke", IDENTITY, [7], False),
                ("result", 0),
                *transmission(),
                0x0E,
            ]:
                if isinstance(item, tuple) and item[:2] == ("invoke", WRITE):
                    code.extend(
                        [
                            ("new", 6, "Ljava/io/DataOutputStream;"),
                            (
                                "invoke",
                                "Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V",
                                [6, 4],
                                False,
                            ),
                            (
                                "invoke",
                                "Ljava/io/OutputStream;->close()V",
                                [closed_register],
                                False,
                            ),
                            ("invoke", WRITE, [output_register, 5], False),
                        ]
                    )
                else:
                    code.append(item)
            with self.subTest(closed=closed_register, output=output_register):
                _, methods = self.program(code)
                self.assertEqual(self.flows(methods)[0], [])

    def test_reopening_file_truncates_only_when_append_is_false(self):
        for append in (False, True):
            code = [
                ("invoke", IDENTITY, [7], False),
                ("result", 0),
                ("invoke", "Ljava/lang/String;->getBytes()[B", [0], False),
                ("result", 0),
                ("string", 1, "/private/data"),
                ("new", 6, "Ljava/io/FileOutputStream;"),
                (
                    "invoke",
                    "Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V",
                    [6, 1],
                    False,
                ),
                ("invoke", "Ljava/io/FileOutputStream;->write([B)V", [6, 0], False),
                ("new", 6, "Ljava/io/FileOutputStream;"),
                0x0212 | int(append) << 12,
                (
                    "invoke",
                    "Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;Z)V",
                    [6, 1, 2],
                    False,
                ),
                ("new", 6, "Ljava/io/FileInputStream;"),
                (
                    "invoke",
                    "Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V",
                    [6, 1],
                    False,
                ),
                ("invoke", "Ljava/io/FileInputStream;->readAllBytes()[B", [6], False),
                ("result", 0),
                *byte_transmission(),
                0x0E,
            ]
            _, methods = self.program(code)
            self.assertEqual(bool(self.flows(methods)[0]), append)

    def test_closed_file_input_does_not_recover_content(self):
        code = [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            ("invoke", "Ljava/lang/String;->getBytes()[B", [0], False),
            ("result", 0),
            ("string", 1, "/private/data"),
            ("new", 6, "Ljava/io/FileOutputStream;"),
            (
                "invoke",
                "Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V",
                [6, 1],
                False,
            ),
            ("invoke", "Ljava/io/FileOutputStream;->write([B)V", [6, 0], False),
            ("new", 6, "Ljava/io/FileInputStream;"),
            (
                "invoke",
                "Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V",
                [6, 1],
                False,
            ),
            ("invoke", "Ljava/io/FileInputStream;->close()V", [6], False),
            ("invoke", "Ljava/io/FileInputStream;->readAllBytes()[B", [6], False),
            ("result", 0),
            *byte_transmission(),
            0x0E,
        ]
        _, methods = self.program(code)
        flows, coverage = self.flows(methods)
        self.assertEqual(flows, [])
        self.assertIn("Closed input stream", json.dumps(coverage))

    def test_byte_array_stream_close_does_not_prevent_later_writes(self):
        _, methods = self.program(
            [
                ("invoke", IDENTITY, [7], False),
                ("result", 0),
                ("invoke", "Ljava/lang/String;->getBytes()[B", [0], False),
                ("result", 0),
                ("new", 6, "Ljava/io/ByteArrayOutputStream;"),
                ("invoke", "Ljava/io/ByteArrayOutputStream;->close()V", [6], False),
                (
                    "invoke",
                    "Ljava/io/ByteArrayOutputStream;->write([B)V",
                    [6, 0],
                    False,
                ),
                (
                    "invoke",
                    "Ljava/io/ByteArrayOutputStream;->toByteArray()[B",
                    [6],
                    False,
                ),
                ("result", 0),
                *byte_transmission(),
                0x0E,
            ]
        )
        self.assertEqual(len(self.flows(methods)[0]), 1)

    def test_integer_expression_controls_branch_without_inventing_a_path(self):
        code = [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            0x3612,
            0x06D8,
            0xFD06,
            0x0639,
            3,
            0x0E,
            *transmission(),
            0x0E,
        ]
        _, methods = self.program(code)
        self.assertEqual(self.flows(methods)[0], [])

    def test_exception_handler_preserves_prior_source_and_records_condition(self):
        code = [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            ("invoke", "Lsample/External;->fail()V", [], True),
            0x0E,
            0x060D,
            *transmission(),
            0x0E,
        ]
        _, methods = self.program(
            definitions=[
                {"signature": ROOT_METHOD, "code": code, "handlers": [(4, 7, 8)]}
            ]
        )
        self.assertEqual(
            methods[0]["handlers"], [{"start": 4, "end": 7, "targets": [8]}]
        )
        flows, coverage = self.flows(methods)
        self.assertEqual(len(flows), 1)
        self.assertTrue(
            any("Exception edge" in part for part in flows[0]["conditions"])
        )
        self.assertEqual(coverage[0]["status"], "PARTIAL")

    def test_unmodeled_recorder_method_is_a_located_gap(self):
        _, methods = self.program(
            [
                ("new", 0, "Landroid/media/MediaRecorder;"),
                (
                    "invoke",
                    "Landroid/media/MediaRecorder;->setNextOutputFile(Ljava/io/File;)V",
                    [0, 1],
                    False,
                ),
                0x0E,
            ]
        )
        flows, coverage = self.flows(methods)
        self.assertEqual(flows, [])
        self.assertIn("Unmodeled recorder invocation", json.dumps(coverage))

    def test_each_p5_boundary_family_is_disclosed(self):
        for signature, registers, reason in (
            (
                "Ldalvik/system/DexClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;",
                [0, 1],
                "dynamic_loading",
            ),
            (
                "Landroid/os/IBinder;->transact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z",
                [0, 1, 2, 3, 4],
                "ipc",
            ),
            (
                "Landroid/webkit/WebView;->evaluateJavascript(Ljava/lang/String;Landroid/webkit/ValueCallback;)V",
                [0, 1, 2],
                "webview_or_script",
            ),
            (
                "Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;",
                [0, 1],
                "reflection",
            ),
        ):
            with self.subTest(reason=reason):
                _, methods = self.program(
                    [("invoke", signature, registers, False), 0x0E]
                )
                flows, coverage = self.flows(methods)
                self.assertEqual(flows, [])
                gaps = coverage[0]["metrics"]["gaps"]
                self.assertTrue(
                    any(
                        reason in item["reason"] and item.get("instruction_offset") == 0
                        for item in gaps
                    )
                )

    def test_loop_and_cleanup_remain_explicit_unknowns(self):
        _, methods = self.program(
            [
                ("new", 0, "Ljava/io/File;"),
                ("string", 1, "/private/clip.mp4"),
                (
                    "invoke",
                    "Ljava/io/File;-><init>(Ljava/lang/String;)V",
                    [0, 1],
                    False,
                ),
                ("invoke", "Ljava/io/File;->delete()Z", [0], False),
                0x0028,
            ]
        )
        flows, coverage = self.flows(methods)
        self.assertEqual(flows, [])
        self.assertIn("File deletion success", json.dumps(coverage))
        self.assertIn("Loop requires additional iterations", json.dumps(coverage))

    def test_feedback_guard_detects_authorized_path_and_prunes_denial(self):
        for granted in (False, True):
            _, methods = self.program(
                [
                    ("invoke", IDENTITY, [7], False),
                    ("result", 0),
                    0x0612 | int(granted) << 12,
                    0x0639,
                    3,
                    0x0E,
                    *transmission(),
                    0x0E,
                ]
            )
            flows, _ = self.flows(methods)
            self.assertEqual(bool(flows), granted)
            if flows:
                self.assertIn("authorization", flows[0]["meaning"])

    def test_signature_digest_path_is_separate_from_installed_inventory(self):
        _, methods = self.program(
            definitions=[
                {
                    "signature": "Lsample/Main;->run(Landroid/content/pm/SigningInfo;)V",
                    "code": [
                        (
                            "invoke",
                            "Landroid/content/pm/SigningInfo;->getApkContentsSigners()[Landroid/content/pm/Signature;",
                            [7],
                            False,
                        ),
                        ("result", 0),
                        0x0112,
                        0x0046,
                        0x0100,
                        (
                            "invoke",
                            "Landroid/content/pm/Signature;->toByteArray()[B",
                            [0],
                            False,
                        ),
                        ("result", 0),
                        (
                            "invoke",
                            "Ljava/security/MessageDigest;->digest([B)[B",
                            [6, 0],
                            False,
                        ),
                        ("result", 0),
                        *byte_transmission(),
                        0x0E,
                    ],
                }
            ]
        )
        flows, _ = self.flows(methods)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["data_category"], "application_fingerprint")

    def test_method_index_budget_is_shared_by_dex_files(self):
        from scripts.static_analysis import dex_ir

        data, _ = self.program()
        apk = make_apk(
            self.root / "multi.apk", entries={"classes.dex": data, "classes2.dex": data}
        )
        artifact = snapshot_file(apk, self.root / "artifacts", self.limits, self.cancel)
        with patch.object(dex_ir, "MAX_INDEXED_METHODS", 1):
            result = analyze_artifact(artifact, self.limits, "standard", self.cancel)
        self.assertEqual(len(result["methods"]), 1)
        self.assertIn("method index budget", json.dumps(result["stages"]))

    def test_field_index_budget_is_shared_by_dex_files(self):
        data, _ = self.program(fields=["Lsample/State;->device:Ljava/lang/String;"])
        apk = make_apk(
            self.root / "fields.apk",
            entries={"classes.dex": data, "classes2.dex": data},
        )
        artifact = snapshot_file(apk, self.root / "artifacts", self.limits, self.cancel)
        result = analyze_artifact(
            artifact, replace(self.limits, max_results=1), "standard", self.cancel
        )
        self.assertEqual(len(result["fields"]), 1)
        self.assertIn("field index budget", json.dumps(result["stages"]))

    def test_important_capabilities_remain_visible_without_telemetry_domains(self):
        for index, text in enumerate(
            (
                "getInstalledPackages queryEvents getIccId imei network openConnection https://private.example/register",
                "MediaProjection AudioRecord Base64 Cipher openConnection https://private.example/detect/app",
            )
        ):
            apk = make_apk(
                self.root / f"clues{index}.apk", entries={"assets/clues.txt": text}
            )
            artifact = snapshot_file(
                apk, self.root / "artifacts", self.limits, self.cancel
            )
            result = analyze_artifact(artifact, self.limits, "standard", self.cancel)
            app = build_apps(
                [artifact], {artifact["sha256"]: result}, None, self.limits, "standard"
            )[0]
            self.assertTrue(app["findings"])
            self.assertTrue(app["priority"]["reasons"])
            self.assertFalse(
                any(item["evidence_level"] in {"E3", "E4"} for item in app["findings"])
            )

    def test_inventory_usage_traffic_and_identifier_share_a_payload(self):
        put = "Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;"
        code = [
            ("new", 6, "Lorg/json/JSONObject;"),
            0x0012,
            (
                "invoke",
                "Landroid/content/pm/PackageManager;->getInstalledPackages(I)Ljava/util/List;",
                [12, 0],
                False,
            ),
            ("result", 1),
            ("string", 5, "apps"),
            ("invoke", put, [6, 5, 1], False),
            0xD807,
            0x0912,
            0x0A16,
            0,
            0x0C17,
            0x5C00,
            0x0526,
            (
                "invoke-range",
                "Landroid/app/usage/UsageStatsManager;->queryUsageStats(IJJ)Ljava/util/List;",
                8,
                6,
                False,
            ),
            ("result", 1),
            ("string", 5, "usage"),
            ("invoke", put, [6, 5, 1], False),
            ("invoke", "Landroid/net/TrafficStats;->getUidRxBytes(I)J", [0], True),
            ("result", 1),
            ("invoke", "Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;", [1, 2], True),
            ("result", 1),
            ("string", 5, "traffic"),
            ("invoke", put, [6, 5, 1], False),
            ("invoke", IDENTITY, [15], False),
            ("result", 1),
            ("string", 5, "imei"),
            ("invoke", put, [6, 5, 1], False),
            (
                "invoke",
                "Lorg/json/JSONObject;->toString()Ljava/lang/String;",
                [6],
                False,
            ),
            ("result", 0),
            *transmission(),
            0x0E,
        ]
        signature = "Lsample/Main;->run(Landroid/content/pm/PackageManager;Landroid/app/usage/UsageStatsManager;Landroid/app/usage/NetworkStatsManager;Landroid/telephony/TelephonyManager;)V"
        _, methods = self.program(
            definitions=[{"signature": signature, "registers": 16, "code": code}]
        )
        flows, _ = self.flows(methods)
        self.assertEqual(
            {item["data_category"] for item in flows},
            {"installed_apps_api", "usage_stats", "network_stats", "device_identifier"},
        )
        usage = next(item for item in flows if item["data_category"] == "usage_stats")
        self.assertIn(
            {"index": 2, "constant": 86400000}, usage["evidence"][0]["arguments"]
        )

    def test_summary_discloses_important_apps_hidden_by_display_limit(self):
        apk = make_apk(
            self.root / "clues.apk", entries={"assets/clues.txt": "MediaProjection"}
        )
        artifact = snapshot_file(apk, self.root / "artifacts", self.limits, self.cancel)
        result = analyze_artifact(artifact, self.limits, "standard", self.cancel)
        app = build_apps(
            [artifact], {artifact["sha256"]: result}, None, self.limits, "standard"
        )[0]
        apps = [{**app, "id": f"app-{index}"} for index in range(25)]
        report = {
            "schema_version": 1,
            "engine_version": "test",
            "run": {},
            "totals": {},
            "limitations": [],
            "apps": apps,
        }
        overview = summary(report)
        self.assertEqual(len(overview["apps"]), 20)
        self.assertEqual(overview["review_required_total"], 25)
        self.assertEqual(overview["review_required_not_shown"], 5)

    def test_source_model_mutation_removes_expected_detection(self):
        _, methods = self.program()
        self.assertTrue(self.flows(methods)[0])
        with patch.dict(SOURCE_METHODS, {}, clear=True):
            flows, coverage = self.flows(methods)
        self.assertFalse(flows)
        self.assertIn("Unmodeled external invocation", json.dumps(coverage))

    def test_split_string_builder_recovers_endpoint_without_domain_rules(self):
        code = [
            ("invoke", IDENTITY, [7], False),
            ("result", 0),
            ("new", 6, "Ljava/lang/StringBuilder;"),
            ("invoke", "Ljava/lang/StringBuilder;-><init>()V", [6], False),
            ("string", 2, "https://private.example"),
            (
                "invoke",
                "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
                [6, 2],
                False,
            ),
            ("string", 2, "/register"),
            (
                "invoke",
                "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
                [6, 2],
                False,
            ),
            (
                "invoke",
                "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;",
                [6],
                False,
            ),
            ("result", 2),
            *[
                item
                for item in transmission()
                if not (isinstance(item, tuple) and item[0] == "string")
            ],
            0x0E,
        ]
        _, methods = self.program(code)
        flows, _ = self.flows(methods)
        self.assertEqual(
            flows[0]["sink"]["endpoints"], ["https://private.example/register"]
        )

    def test_quick_mode_defers_dataflow_and_preserves_candidates(self):
        data, _ = self.program()
        apk = make_apk(self.root / "quick.apk", entries={"classes.dex": data})
        artifact = snapshot_file(apk, self.root / "artifacts", self.limits, self.cancel)
        result = analyze_artifact(artifact, self.limits, "quick", self.cancel)
        app = build_apps(
            [artifact], {artifact["sha256"]: result}, None, self.limits, "quick"
        )[0]
        self.assertTrue(app["findings"])
        self.assertTrue(
            all(
                item["status"] == "DEFERRED"
                for item in app["coverage"]
                if "dataflow" in item["stage"]
            )
        )
        self.assertFalse(
            any(item["evidence_level"] in {"E3", "E4"} for item in app["findings"])
        )

    def test_models_and_fields_produce_visible_signals_without_false_e2(self):
        for signature, expected in SOURCE_METHODS.items():
            with self.subTest(signature=signature):
                matches = signal_matches(signature, {"kind": "dex_invocation"}, "E2")
                self.assertIn(expected, {item["type"] for item in matches})
        for signature in AUDIO_READS:
            self.assertIn(
                "audio_capture",
                {item["type"] for item in signal_matches(signature, {}, "E2")},
            )
        self.assertEqual(
            signal_matches("Lsample/Fake;->getImei()Ljava/lang/String;", {}, "E2"), []
        )
        self.assertIn(
            "identifier_field",
            {item["type"] for item in signal_matches("imei imsi iccid", {})},
        )

    def test_precise_privacy_models_preserve_other_existing_invocation_rules(self):
        for signature, category in (
            (
                "Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;",
                "location_api",
            ),
            (
                "Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;",
                "sms_api",
            ),
            (
                "Landroid/content/ClipboardManager;->getPrimaryClip()Landroid/content/ClipData;",
                "clipboard_api",
            ),
            (
                "Landroid/provider/ContactsContract$Contacts;->lookupContact(Landroid/content/ContentResolver;Landroid/net/Uri;)Landroid/net/Uri;",
                "contacts_api",
            ),
        ):
            with self.subTest(category=category):
                matches = signal_matches(signature, {"kind": "dex_invocation"}, "E2")
                self.assertIn(category, {item["type"] for item in matches})

    def test_cli_sqlite_json_queries_cache_and_multigeneration_resume(self):
        data, _ = self.program()
        apk = make_apk(self.root / "input.apk", entries={"classes.dex": data})
        previous = None
        for generation in range(3):
            output = self.root / f"task{generation}"
            command = [
                sys.executable,
                str(ROOT / "scripts/analyze.py"),
                "scan",
                "--output",
                str(output),
            ]
            command += ["--resume", str(previous)] if previous else ["--apk", str(apk)]
            completed = subprocess.run(
                command, check=False, capture_output=True, text=True, timeout=30
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = load_report(output / "analysis.sqlite3")
            try:
                self.assertTrue(
                    any("runtime evidence" in item for item in report["limitations"])
                )
                flows = [
                    item
                    for item in query(report, "findings")["items"]
                    if item["type"] == "privacy_transmission_path"
                ]
                self.assertEqual(len(flows), 1)
                self.assertEqual(query(report, "methods")["total"], 1)
                for identity in flows[0]["evidence_ids"]:
                    self.assertEqual(
                        query(report, "evidence", identity=identity)["total"], 1
                    )
                exported = load_report(output / "analysis.json")
                self.assertEqual(query(report, "findings"), query(exported, "findings"))
                self.assertEqual(summary(report), summary(exported))
            finally:
                close_report(report)
            previous = output

    def test_split_method_resolution_and_package_isolation(self):
        helper = "Lsample/Send;->send(Ljava/lang/String;)V"
        definitions = [
            [
                {
                    "signature": ROOT_METHOD,
                    "code": [
                        ("invoke", IDENTITY, [7], False),
                        ("result", 0),
                        ("invoke", helper, [0], True),
                        0x0E,
                    ],
                }
            ],
            [{"signature": helper, "code": [*transmission(7), 0x0E]}],
        ]
        for separate in (False, True):
            with self.subTest(separate=separate):
                store = AnalysisStore(
                    self.root / f"split-{separate}.sqlite3", cancel=self.cancel
                )
                try:
                    artifacts = []
                    for index, methods in enumerate(definitions):
                        data, _ = self.program(definitions=methods)
                        apk = make_apk(
                            self.root / f"{separate}-{index}.apk",
                            package=f"sample.app{index}" if separate else "sample.app",
                            split="feature" if index else None,
                            entries={"classes.dex": data},
                        )
                        artifact = snapshot_file(
                            apk, self.root / "artifacts", self.limits, self.cancel
                        )
                        artifacts.append(artifact)
                        store.save_artifact(
                            artifact["sha256"],
                            analyze_artifact(
                                artifact, self.limits, "standard", self.cancel
                            ),
                        )
                    apps = build_apps(
                        artifacts,
                        ArtifactResults(store),
                        None,
                        self.limits,
                        "standard",
                        store,
                    )
                    flows = [
                        item
                        for app in apps
                        for item in app["findings"]
                        if item["type"] == "privacy_transmission_path"
                    ]
                    self.assertEqual(bool(flows), not separate)
                finally:
                    store.close()

    def test_rule_and_model_identities_change_cache_keys(self):
        original = cache_key("artifact", self.limits, "standard")
        with patch("scripts.static_analysis.engine.MODEL_VERSION", "updated"):
            self.assertNotEqual(
                cache_key("artifact", self.limits, "standard"), original
            )
        with patch("scripts.static_analysis.engine.RULE_VERSION", "updated"):
            self.assertNotEqual(
                cache_key("artifact", self.limits, "standard"), original
            )
