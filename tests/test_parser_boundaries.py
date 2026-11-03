import hashlib
import struct
import tempfile
import threading
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from support import make_apk, make_axml, make_dex, make_pool, uleb

from scripts.static_analysis import binary, common, engine
from scripts.static_analysis.common import (
    MEMORY_BUDGET_MESSAGE,
    Budget,
    BudgetExceeded,
    Cancelled,
    Limits,
    MemoryBudgetExceeded,
)
from scripts.static_analysis.storage import AnalysisStore

MAX_RECORDS_AFTER_STOP = 256
REPEATED_TABLE_ITEMS = 2048


class ParserBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.limits = Limits()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def dex_table(self, section):
        data = bytearray(make_dex())
        count = REPEATED_TABLE_ITEMS
        start = len(data)
        if section == "types":
            stride, method = 4, "u32"
            data.extend(struct.pack("<I", 1) * count)
            struct.pack_into("<II", data, 64, count, start)
        elif section == "prototypes":
            stride, method = 12, "u32"
            data.extend(struct.pack("<III", 4, 3, 0) * count)
            struct.pack_into("<II", data, 72, count, start)
            start += 4
        elif section == "parameters":
            stride, method = 2, "u16"
            data.extend(struct.pack("<I", count) + struct.pack("<H", 3) * count)
            original_prototypes = struct.unpack_from("<I", data, 76)[0]
            struct.pack_into("<I", data, original_prototypes + 8, start)
            start += 4
        elif section == "methods":
            stride, method = 8, "u16"
            data.extend(struct.pack("<HHI", 0, 0, 5) * count)
            struct.pack_into("<II", data, 88, count, start)
            start += 2
        else:
            field_section = section in {"fields", "instance_fields"}
            stride, method = (2 if field_section else 3), "uleb"
            class_offset = struct.unpack_from("<I", data, 100)[0]
            original_class_data = struct.unpack_from("<I", data, class_offset + 24)[0]
            struct.pack_into("<I", data, class_offset + 24, start)
            if field_section:
                header = (
                    uleb(count) + b"\x00"
                    if section == "fields"
                    else b"\x00" + uleb(count)
                ) + b"\x01\x00"
                methods = bytes(data[original_class_data + 4 : start])
                data.extend(header + b"\x00\x00" * count + methods)
            else:
                header = b"\x00\x00" + (
                    uleb(count) + b"\x00"
                    if section == "empty_methods"
                    else b"\x00" + uleb(count)
                )
                data.extend(header + b"\x00\x09\x00" * count)
            start += len(header)
        struct.pack_into("<I", data, 32, len(data))
        data_offset = struct.unpack_from("<I", data, 108)[0]
        struct.pack_into("<I", data, 104, len(data) - data_offset)
        data[12:32] = hashlib.sha1(memoryview(data)[32:]).digest()
        struct.pack_into(
            "<I", data, 8, zlib.adler32(memoryview(data)[12:]) & 0xFFFFFFFF
        )
        return bytes(data), method, start, stride, count

    def assert_mid_parse_stop(
        self, operation, method, start, stride, count, stop, partial=False, trigger_at=5
    ):
        state = {"reads": 0, "requested": False}
        cancel = threading.Event()
        original = getattr(binary.BinaryReader, method)

        def observed(reader, offset):
            value = original(reader, offset)
            if (
                start <= offset < start + stride * count
                and (offset - start) % stride == 0
            ):
                state["reads"] += 1
                if state["reads"] == trigger_at:
                    state["requested"] = True
                    if stop == "cancel":
                        cancel.set()
            return value

        error_type = {
            "cancel": Cancelled,
            "timeout": BudgetExceeded,
            "memory": MemoryBudgetExceeded,
        }[stop]
        limits = Limits(timeout=1, memory_bytes=1)
        with (
            patch.object(binary.BinaryReader, method, observed),
            patch.object(
                common.time,
                "monotonic",
                side_effect=lambda: (
                    2 if state["requested"] and stop == "timeout" else 0
                ),
            ),
            patch.object(
                common,
                "resident_bytes",
                side_effect=lambda: 2 if state["requested"] and stop == "memory" else 0,
            ),
        ):
            budget = Budget(limits, cancel)
            if partial and stop == "timeout":
                result = operation(limits, budget)
                self.assertIn("Artifact time budget exceeded", result["gaps"])
            else:
                with self.assertRaises(error_type):
                    operation(limits, budget)
        self.assertTrue(state["requested"])
        self.assertLessEqual(state["reads"] - trigger_at, MAX_RECORDS_AFTER_STOP)

    def test_resource_and_xml_string_pools_observe_mid_pool_stops(self):
        for utf8 in (False, True):
            for source in ("resources", "xml"):
                if source == "xml":
                    original = make_axml()
                    values = [
                        item["value"]
                        for item in binary.resource_strings(
                            original, self.limits, Budget(self.limits)
                        )
                    ]
                    values.extend(["value"] * REPEATED_TABLE_ITEMS)
                    pool = make_pool(values, utf8=utf8)
                    old_pool_size = struct.unpack_from("<I", original, 12)[0]
                    body = pool + original[8 + old_pool_size :]
                    data = struct.pack("<HHI", 3, 8, 8 + len(body)) + body
                    start = 8 + 28
                    parser = binary.xml_nodes
                else:
                    values = ["value"] * REPEATED_TABLE_ITEMS
                    data = make_pool(values, utf8=utf8)
                    start = 28
                    parser = binary.resource_strings
                expected = parser(data, self.limits, Budget(self.limits))
                self.assertTrue(expected)
                for stop in ("cancel", "timeout", "memory"):
                    with self.subTest(utf8=utf8, source=source, stop=stop):
                        self.assert_mid_parse_stop(
                            lambda limits, budget, parser=parser, data=data: parser(
                                data, limits, budget
                            ),
                            "u32",
                            start,
                            4,
                            len(values),
                            stop,
                        )

    def test_dex_non_instruction_tables_observe_mid_table_stops(self):
        for section in (
            "types",
            "prototypes",
            "parameters",
            "methods",
            "fields",
            "instance_fields",
            "empty_methods",
            "virtual_methods",
        ):
            data, method, start, stride, count = self.dex_table(section)
            for inspect_code in (False, True):
                partial = section in {
                    "fields",
                    "instance_fields",
                    "empty_methods",
                    "virtual_methods",
                }
                if partial and not inspect_code:
                    continue
                expected = binary.dex_index(
                    data, self.limits, Budget(self.limits), inspect_code=inspect_code
                )
                self.assertEqual(expected["gaps"], [])
                for stop in ("cancel", "timeout", "memory"):
                    with self.subTest(
                        section=section, inspect_code=inspect_code, stop=stop
                    ):
                        self.assert_mid_parse_stop(
                            lambda limits, budget, data=data, inspect_code=inspect_code: (
                                binary.dex_index(
                                    data, limits, budget, inspect_code=inspect_code
                                )
                            ),
                            method,
                            start,
                            stride,
                            count,
                            stop,
                            partial=partial,
                        )

    def test_short_parser_phases_check_stop_before_returning(self):
        dex = make_dex()
        type_start = struct.unpack_from("<I", dex, 68)[0]
        for stop in ("cancel", "timeout", "memory"):
            with self.subTest(source="resources", stop=stop):
                self.assert_mid_parse_stop(
                    lambda limits, budget: binary.resource_strings(
                        make_pool(["value"]), limits, budget
                    ),
                    "u32",
                    28,
                    4,
                    1,
                    stop,
                    trigger_at=1,
                )
            with self.subTest(source="dex", stop=stop):
                self.assert_mid_parse_stop(
                    lambda limits, budget: binary.dex_index(
                        dex, limits, budget, inspect_code=False
                    ),
                    "u32",
                    type_start,
                    4,
                    5,
                    stop,
                    trigger_at=1,
                )

    def test_parser_stops_preserve_checkpoint_flags_and_recovery(self):
        for section in ("resources", "prototypes", "virtual_methods"):
            if section == "resources":
                data = make_pool(["https://pool.example.org/a"] * REPEATED_TABLE_ITEMS)
                method, start, stride, count = "u32", 28, 4, REPEATED_TABLE_ITEMS
                entry = "resources.arsc"
            else:
                data, method, start, stride, count = self.dex_table(section)
                entry = "classes.dex"
            artifact = common.snapshot_file(
                make_apk(self.root / f"{section}.apk", entries={entry: data}),
                self.root / "artifacts",
                self.limits,
                threading.Event(),
            )
            for mode in ("quick", "standard", "decompile"):
                if section == "virtual_methods" and mode == "quick":
                    continue
                expected = engine.analyze_artifact(
                    artifact, self.limits, mode, threading.Event()
                )
                for stop in ("cancel", "timeout", "memory"):
                    with self.subTest(section=section, mode=mode, stop=stop):
                        state = {"reads": 0, "requested": False, "raised": False}
                        cancel = threading.Event()
                        error = (
                            BudgetExceeded("Artifact time budget exceeded")
                            if stop == "timeout"
                            else MemoryBudgetExceeded(MEMORY_BUDGET_MESSAGE)
                            if stop == "memory"
                            else None
                        )
                        original = getattr(binary.BinaryReader, method)

                        class InterruptedBudget(Budget):
                            def check(self, state=state, error=error):
                                if state["requested"] and not state["raised"] and error:
                                    state["raised"] = True
                                    raise error
                                super().check()

                        def observed(
                            reader,
                            offset,
                            state=state,
                            start=start,
                            stride=stride,
                            count=count,
                            original=original,
                            stop=stop,
                            cancel=cancel,
                        ):
                            value = original(reader, offset)
                            if (
                                start <= offset < start + stride * count
                                and (offset - start) % stride == 0
                            ):
                                state["reads"] += 1
                                if state["reads"] == 5:
                                    state["requested"] = True
                                    if stop == "cancel":
                                        cancel.set()
                            return value

                        source = AnalysisStore(
                            self.root / f"{section}-{mode}-{stop}.sqlite3"
                        )
                        self.addCleanup(source.close)
                        events = []
                        with (
                            patch.object(binary.BinaryReader, method, observed),
                            patch.object(engine, "Budget", InterruptedBudget),
                        ):
                            results = engine.analyze_many(
                                [artifact],
                                self.limits,
                                mode,
                                cancel,
                                1,
                                None,
                                events.append,
                                store=source,
                            )
                        self.assertTrue(state["requested"])
                        self.assertLessEqual(state["reads"] - 5, MAX_RECORDS_AFTER_STOP)
                        result = results[artifact["sha256"]]
                        self.assertEqual(result["manifest"], expected["manifest"])
                        self.assertEqual(
                            bool(result.get("resource_limited")), stop == "memory"
                        )
                        self.assertEqual(cancel.is_set(), stop != "timeout")
                        self.assertEqual(
                            events[-1]["status"],
                            "CANCELLED" if stop == "cancel" else "PARTIAL",
                        )
                        key = engine.cache_key(artifact["sha256"], self.limits, mode)
                        self.assertEqual(
                            source.reusable(artifact["sha256"], key, False),
                            stop == "timeout",
                        )
                        self.assertFalse(source.reusable(artifact["sha256"], key, True))
                        before = source.path.read_bytes()
                        for retry in (False, True):
                            cancel.clear()
                            target = AnalysisStore(
                                self.root / f"{section}-{mode}-{stop}-{retry}.sqlite3"
                            )
                            self.addCleanup(target.close)
                            with patch.object(
                                engine,
                                "analyze_artifact",
                                wraps=engine.analyze_artifact,
                            ) as parser:
                                recovered = engine.analyze_many(
                                    [artifact],
                                    self.limits,
                                    mode,
                                    cancel,
                                    1,
                                    None,
                                    lambda event: None,
                                    store=target,
                                    resume_store=source,
                                    retry_incomplete=retry,
                                )
                            reparsed = stop != "timeout" or retry
                            self.assertEqual(parser.call_count, int(reparsed))
                            if reparsed:
                                for category in ("endpoints", "signals", "sdks"):
                                    self.assertEqual(
                                        list(recovered[artifact["sha256"]][category]),
                                        expected[category],
                                    )
                            self.assertEqual(source.path.read_bytes(), before)

    def test_aliased_string_pool_checks_decoded_bytes_during_expansion(self):
        payload = make_pool(["a" * 8192])[32:]
        count = REPEATED_TABLE_ITEMS
        start = 28 + count * 4
        data = (
            struct.pack("<HH6I", 1, 28, start + len(payload), count, 0, 0x100, start, 0)
            + bytes(count * 4)
            + payload
        )
        reads = 0
        original = binary.BinaryReader.u32

        def observed(reader, offset):
            nonlocal reads
            if 28 <= offset < start:
                reads += 1
            return original(reader, offset)

        with (
            patch.object(binary.BinaryReader, "u32", observed),
            patch.object(common, "resident_bytes", side_effect=lambda: reads * 8192),
            self.assertRaisesRegex(MemoryBudgetExceeded, MEMORY_BUDGET_MESSAGE),
        ):
            binary.resource_strings(
                data, self.limits, Budget(Limits(memory_bytes=256 * 1024))
            )
        self.assertLessEqual(reads, 128)


if __name__ == "__main__":
    unittest.main()
