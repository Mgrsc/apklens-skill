import json
import multiprocessing
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from support import make_apk, make_axml, make_dex, make_pool

from scripts.static_analysis import binary, engine
from scripts.static_analysis.common import (
    AnalysisDeadline,
    AnalysisError,
    Budget,
    Limits,
    snapshot_file,
)
from scripts.static_analysis.reports import close_report, load_report, summary
from scripts.static_analysis.rules import signal_decisions
from scripts.static_analysis.storage import AnalysisStore, artifact_status

ROOT = Path(__file__).resolve().parents[1]


def encoded_pool(raw, units):
    payload = bytes([units, len(raw)]) + raw + b"\x00"
    payload += b"\x00" * (-len(payload) % 4)
    return struct.pack("<HH7I", 1, 28, 32 + len(payload), 1, 0, 256, 32, 0, 0) + payload


class BoundedReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.limits = Limits()
        self.cancel = threading.Event()

    def decode(self, pool):
        return binary.resource_strings(pool, self.limits, Budget(self.limits))

    def test_resource_scalar_and_surrogate_pair_encodings_agree(self):
        value = "https://example.org/\U0001f31a"
        units = value.encode("utf-16-le")
        paired = "".join(
            chr(unit).encode("utf-8", "surrogatepass").decode("latin1")
            for unit in struct.unpack("<" + "H" * (len(units) // 2), units)
        ).encode("latin1")
        for pool in (
            make_pool([value]),
            make_pool([value], utf8=False),
            encoded_pool(paired, len(units) // 2),
        ):
            with self.subTest(pool=pool.hex()):
                result = self.decode(pool)
                self.assertEqual(result[0]["value"], value)
                json.dumps(result, ensure_ascii=False).encode("utf-8")

    def test_resource_invalid_sequences_lengths_and_terminators_fail(self):
        for raw, units in (
            (b"\xed\xa0\x80", 1),
            (b"\xed\xb0\x80", 1),
            (b"\xed\xb0\x80\xed\xa0\x80", 2),
            (b"\xc1\x81", 1),
            (b"\xf4\x90\x80\x80", 2),
            (b"valid", 2),
        ):
            with (
                self.subTest(raw=raw, units=units),
                self.assertRaises((AnalysisError, UnicodeError)),
            ):
                self.decode(encoded_pool(raw, units))
        pool = bytearray(encoded_pool(b"valid", 5))
        pool[39] = 1
        with self.assertRaises(AnalysisError):
            self.decode(bytes(pool))

    def test_valid_pair_resources_preserve_endpoints_and_sqlite_serialization(self):
        raw = b"https://example.org/\xed\xa0\xbc\xed\xbc\x99"
        value = "https://example.org/\U0001f319"
        path = make_apk(
            self.root / "input.apk",
            entries={
                "resources.arsc": encoded_pool(raw, len(value.encode("utf-16-le")) // 2)
            },
        )
        artifact = snapshot_file(
            path, self.root / "artifacts", self.limits, self.cancel
        )
        result = engine.analyze_artifact(artifact, self.limits, "standard", self.cancel)
        self.assertNotEqual(artifact_status(result), "FAILED")
        self.assertTrue(
            any(item["host"] == "example.org" for item in result["endpoints"])
        )
        with closing(AnalysisStore(self.root / "facts.sqlite3")) as store:
            store.save_artifact(artifact["sha256"], result)
            self.assertTrue(list(store.artifact(artifact["sha256"])["endpoints"]))

    def test_ui_and_parameter_types_do_not_become_direct_sensitive_calls(self):
        for value in (
            "Landroid/view/View;->dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z",
            "Landroid/view/MotionEvent;->getAction()I",
            "Lsample/Handler;->onEvent(Ljava/lang/Object;)V",
            "Lsample/Handler;-><init>(Landroid/location/LocationManager;)V",
        ):
            with self.subTest(value=value):
                self.assertNotIn("telemetry_event", signal_decisions(value, "E2"))
                self.assertNotIn("location_api", signal_decisions(value, "E2"))
        self.assertNotIn("telemetry_event", signal_decisions("MotionEvent", "E1"))
        self.assertIn(
            "location_api", signal_decisions("Landroid/location/LocationManager;", "E1")
        )

    def test_real_event_and_location_calls_remain_candidates(self):
        for value in (
            "Lcom/google/firebase/analytics/FirebaseAnalytics;->logEvent(Ljava/lang/String;Landroid/os/Bundle;)V",
            "Lcom/umeng/analytics/MobclickAgent;->onEvent(Landroid/content/Context;Ljava/lang/String;)V",
            "Lio/sentry/Sentry;->captureException(Ljava/lang/Throwable;)Lio/sentry/protocol/SentryId;",
        ):
            self.assertIn("telemetry_event", signal_decisions(value, "E2"))
        for value in (
            "Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;",
            "Landroid/location/Location;->getLatitude()D",
            "Lcom/google/android/gms/location/FusedLocationProviderClient;->getLastLocation()Lcom/google/android/gms/tasks/Task;",
        ):
            self.assertIn("location_api", signal_decisions(value, "E2"))

    def artifacts(self):
        return [
            snapshot_file(
                make_apk(
                    self.root / f"input-{index}.apk",
                    package=f"com.example.app{index}",
                    entries={
                        "classes.dex": make_dex(url=f"https://example.org/{index}")
                    },
                ),
                self.root / "artifacts",
                self.limits,
                self.cancel,
            )
            for index in range(3)
        ]

    def test_deadline_observes_monotonic_elapsed_time(self):
        with patch("scripts.static_analysis.common.time.monotonic", return_value=50):
            deadline = AnalysisDeadline(10)
        with patch("scripts.static_analysis.common.time.monotonic", return_value=59):
            self.assertEqual(deadline.remaining(), 1)
            self.assertFalse(deadline.exhausted)
        with patch("scripts.static_analysis.common.time.monotonic", return_value=60):
            self.assertTrue(deadline.expired())
            self.assertTrue(deadline.exhausted)

    def test_deadline_drains_inflight_work_and_preserves_every_target(self):
        artifacts = self.artifacts()
        for executor in ("thread", "process"):
            with self.subTest(executor=executor):
                deadline = AnalysisDeadline(300)

                def complete(event, deadline=deadline):
                    if event["event"] == "artifact_complete":
                        deadline.started -= 600

                with closing(AnalysisStore(self.root / f"{executor}.sqlite3")) as store:
                    results = engine.analyze_many(
                        artifacts,
                        self.limits,
                        "standard",
                        self.cancel,
                        1,
                        None,
                        complete,
                        store=store,
                        executor_kind=executor,
                        deadline=deadline,
                    )
                    states = [artifact_status(item) for item in results.values()]
                    self.assertEqual(states.count("COMPLETE"), 1)
                    self.assertEqual(states.count("PARTIAL"), 2)
                    self.assertFalse(self.cancel.is_set())
                    snapshot = {
                        "serial": "test-device",
                        "user": 0,
                        "packages": {"com.example.metadata": {"stages": []}},
                    }
                    with patch.object(engine, "analyze_dataflow") as dataflow:
                        apps = engine.build_apps(
                            artifacts,
                            results,
                            snapshot,
                            self.limits,
                            "standard",
                            store=store,
                            deadline=deadline,
                        )
                    dataflow.assert_not_called()
                    self.assertEqual(len(apps), 4)
                    self.assertTrue(any(app["endpoints"] for app in apps))
                    for app in apps:
                        stages = [
                            item
                            for item in app["coverage"]
                            if item["stage"] == "method_dataflow_E3"
                        ]
                        self.assertEqual(stages[0]["status"], "DEFERRED")
                        self.assertNotIn("metrics", stages[0])
                self.assertEqual(multiprocessing.active_children(), [])
                self.assertFalse(list(self.root.glob(".workers-*")))

    def test_dataflow_receives_only_remaining_budget(self):
        artifact = self.artifacts()[0]
        result = engine.analyze_artifact(artifact, self.limits, "standard", self.cancel)
        deadline = AnalysisDeadline(300)
        deadline.started -= 295
        original = engine.analyze_dataflow
        observed = []

        def dataflow(methods, limits, *args, **kwargs):
            observed.append(limits.timeout)
            return original(methods, limits, *args, **kwargs)

        with patch.object(engine, "analyze_dataflow", side_effect=dataflow):
            apps = engine.build_apps(
                [artifact],
                {artifact["sha256"]: result},
                None,
                self.limits,
                "standard",
                deadline=deadline,
            )
        self.assertEqual(len(apps), 1)
        self.assertEqual(len(observed), 1)
        self.assertGreater(observed[0], 0)
        self.assertLessEqual(observed[0], 5)

    def test_expired_cli_exports_partial_register_and_resumes_in_new_directory(self):
        inputs = self.artifacts()
        output = self.root / "expired"
        command = [
            "scan",
            "--output",
            str(output),
            "--no-cache",
            "--quiet",
            "--analysis-timeout",
            "1",
        ]
        for artifact in inputs:
            command.extend(["--apk", artifact["path"]])
        source = (
            "import sys; sys.path.insert(0, 'scripts'); import analyze; "
            "from static_analysis.common import AnalysisDeadline; "
            "analyze.AnalysisDeadline = lambda seconds: AnalysisDeadline(0); "
            "raise SystemExit(analyze.main())"
        )
        result = subprocess.run(
            [sys.executable, "-c", source, *command],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "PARTIAL")
        report = load_report(output / "analysis.sqlite3")
        try:
            self.assertEqual(report["run"]["stop_reason"], "analysis_timeout")
            self.assertEqual(len(report["apps"]), 3)
            self.assertEqual(summary(report)["facts"]["applications"]["with_apk"], 3)
        finally:
            close_report(report)
        for name in (
            "summary.json",
            "report.md",
            "analysis.json",
            "domains.txt",
            "snapshot.json",
        ):
            self.assertTrue((output / name).is_file(), name)
        resumed = subprocess.run(
            [
                sys.executable,
                "scripts/analyze.py",
                "scan",
                "--resume",
                str(output),
                "--output",
                str(self.root / "resumed"),
                "--no-cache",
                "--quiet",
                "--retry-incomplete",
                "--analysis-timeout",
                "60",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        report = load_report(self.root / "resumed" / "analysis.sqlite3")
        try:
            self.assertIsNone(report["run"]["stop_reason"])
            self.assertTrue(all(app["manifests"] for app in report["apps"]))
        finally:
            close_report(report)

    def test_binary_xml_accepts_paired_scalars_and_rejects_isolated_surrogates(self):
        original = make_axml()
        pool_size = struct.unpack_from("<I", original, 12)[0]
        values = [item["value"] for item in self.decode(original[8 : 8 + pool_size])]
        for raw, scalar in (
            (b"\xed\xa0\xbc\xed\xbc\x99", "\U0001f319"),
            (b"\xed\xa0\xbc", None),
        ):
            values[2] = "com.example." + (scalar or "\U0001f319")
            pool = bytearray(make_pool(values))
            index = binary.string_pool(
                binary.BinaryReader(pool), 0, self.limits, Budget(self.limits)
            )[2]
            position = index["offset"]
            source = values[2].encode()
            replaced = b"com.example." + raw
            end = position + len(source)
            pool[position:end] = replaced
            difference = len(replaced) - len(source)
            pool[position - 1] = len(replaced)
            if scalar is None:
                pool[position - 2] -= 1
            for i in range(3, len(values)):
                offset = struct.unpack_from("<I", pool, 28 + i * 4)[0]
                struct.pack_into("<I", pool, 28 + i * 4, offset + difference)
            pool.extend(b"\x00" * (-len(pool) % 4))
            struct.pack_into("<I", pool, 4, len(pool))
            document = bytearray(original[:8] + pool + original[8 + pool_size :])
            struct.pack_into("<I", document, 4, len(document))
            if scalar:
                nodes = binary.xml_nodes(document, self.limits, Budget(self.limits))
                self.assertEqual(nodes[0]["attrs"]["package"], values[2])
            else:
                with self.assertRaises(UnicodeError):
                    binary.xml_nodes(document, self.limits, Budget(self.limits))

    def test_decompilation_and_source_reading_share_one_timeout(self):
        output = self.root / "sources"
        output.mkdir()
        (output / "Target.java").write_text(
            'class Target { String host = "https://example.org"; }'
        )
        clock = [0]

        def decompile(*args, **kwargs):
            clock[0] = 2
            return {"status": "COMPLETE", "reason": None}

        with (
            patch(
                "scripts.static_analysis.common.time.monotonic",
                side_effect=lambda: clock[0],
            ),
            patch.object(engine, "run_command", side_effect=decompile),
        ):
            result = engine.source_view(
                {"sha256": "a" * 64, "path": "input.apk"},
                output,
                "jadx",
                Limits(timeout=1),
                self.cancel,
            )
        self.assertFalse(result["endpoints"])
        self.assertTrue(
            any("time budget" in item.get("reason", "") for item in result["stages"])
        )
