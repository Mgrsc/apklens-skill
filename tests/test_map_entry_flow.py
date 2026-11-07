import unittest

import test_privacy_dataflow as privacy_tests
from privacy_fixtures import IDENTITY, ROOT_METHOD, transmission

ENTRY_SET = "Ljava/util/Map;->entrySet()Ljava/util/Set;"
ITERATOR = "Ljava/util/Set;->iterator()Ljava/util/Iterator;"
NEXT = "Ljava/util/Iterator;->next()Ljava/lang/Object;"
VALUE = "Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;"
PUT = "Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"
USAGE = "Landroid/app/usage/UsageStatsManager;->queryAndAggregateUsageStats(JJ)Ljava/util/Map;"


def entry_value(register=0, getter=VALUE):
    return [
        ("invoke", ENTRY_SET, [register], False),
        ("result", 0),
        ("invoke", ITERATOR, [0], False),
        ("result", 0),
        ("invoke", NEXT, [0], False),
        ("result", 0),
        ("invoke", getter, [0], False),
        ("result", 0),
    ]


class MapEntryFlowTests(unittest.TestCase):
    def setUp(self):
        self.harness = privacy_tests.PrivacyTests()
        self.harness.setUp()
        self.addCleanup(self.harness.doCleanups)

    def flows(self, code):
        _, methods = self.harness.program(code=code)
        return self.harness.flows(methods)

    def test_usage_map_values_reach_the_payload(self):
        flows, _ = self.flows(
            [
                ("invoke", USAGE, [7, 2, 3, 4, 5], False),
                ("result", 0),
                *entry_value(),
                (
                    "invoke",
                    "Landroid/app/usage/UsageStats;->getPackageName()Ljava/lang/String;",
                    [0],
                    False,
                ),
                ("result", 0),
                *transmission(),
                0x0E,
            ]
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["data_category"], "usage_stats")
        targets = [item.get("excerpt") for item in flows[0]["evidence"]]
        for signature in (ENTRY_SET, ITERATOR, NEXT, VALUE):
            self.assertIn(signature, targets)

    def test_stored_values_propagate_but_keys_and_replaced_values_do_not(self):
        for variant in ("value", "key", "replaced", "separate", "get_key", "cleared"):
            with self.subTest(variant=variant):
                code = [
                    ("invoke", IDENTITY, [7], False),
                    ("result", 6),
                    ("new", 0, "Ljava/util/HashMap;"),
                    ("invoke", "Ljava/util/HashMap;-><init>()V", [0], False),
                    ("string", 1, "public"),
                    (
                        "invoke",
                        PUT,
                        [0, 6, 1] if variant == "key" else [0, 1, 6],
                        False,
                    ),
                ]
                if variant == "replaced":
                    code += [("invoke", PUT, [0, 1, 1], False)]
                elif variant == "separate":
                    code += [("new", 0, "Ljava/util/HashMap;")]
                elif variant == "cleared":
                    code += [("invoke", "Ljava/util/Map;->clear()V", [0], False)]
                code += entry_value(
                    getter="Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;"
                    if variant == "get_key"
                    else VALUE
                )
                flows, _ = self.flows([*code, *transmission(), 0x0E])
                self.assertEqual(bool(flows), variant == "value")

    def test_backing_map_mutations_are_read_when_the_entry_value_is_requested(self):
        for mutate_at in (2, 4, 6):
            for mutation in ("clear", "overwrite"):
                with self.subTest(mutate_at=mutate_at, mutation=mutation):
                    steps = entry_value()
                    steps[0] = ("invoke", ENTRY_SET, [5], False)
                    change = (
                        ("invoke", "Ljava/util/Map;->clear()V", [5], False)
                        if mutation == "clear"
                        else ("invoke", PUT, [5, 1, 1], False)
                    )
                    code = [
                        ("invoke", IDENTITY, [7], False),
                        ("result", 6),
                        ("new", 5, "Ljava/util/HashMap;"),
                        ("string", 1, "public"),
                        ("invoke", PUT, [5, 1, 6], False),
                        *steps[:mutate_at],
                        change,
                        *steps[mutate_at:],
                        *transmission(),
                        0x0E,
                    ]
                    flows, _ = self.flows(code)
                    self.assertFalse(flows)

    def test_entry_names_on_unmodeled_owners_do_not_propagate(self):
        _, methods = self.harness.program(
            definitions=[
                {
                    "signature": ROOT_METHOD,
                    "code": [
                        ("invoke", IDENTITY, [7], False),
                        ("result", 0),
                        (
                            "invoke",
                            "Lsample/Entry;->getValue()Ljava/lang/Object;",
                            [0],
                            False,
                        ),
                        ("result", 0),
                        *transmission(),
                        0x0E,
                    ],
                }
            ]
        )
        flows, coverage = self.harness.flows(methods)
        self.assertFalse(flows)
        self.assertTrue(any(item["status"] == "PARTIAL" for item in coverage))

    def test_existing_entry_updates_are_visible_through_the_view(self):
        for update_at in (2, 4, 6):
            with self.subTest(update_at=update_at):
                steps = entry_value(register=5)
                flows, _ = self.flows(
                    [
                        ("invoke", IDENTITY, [7], False),
                        ("result", 6),
                        ("new", 5, "Ljava/util/HashMap;"),
                        ("string", 1, "public"),
                        ("invoke", PUT, [5, 1, 1], False),
                        *steps[:update_at],
                        ("invoke", PUT, [5, 1, 6], False),
                        *steps[update_at:],
                        *transmission(),
                        0x0E,
                    ]
                )
                self.assertTrue(flows)

    def test_source_map_clear_and_unmodeled_entry_calls_stop_propagation(self):
        for mutation in ("clear", "unmodeled"):
            with self.subTest(mutation=mutation):
                steps = entry_value(register=5)
                call = (
                    ("invoke", "Ljava/util/Map;->clear()V", [5], False)
                    if mutation == "clear"
                    else (
                        "invoke",
                        "Lsample/Mutator;->change(Ljava/lang/Object;)V",
                        [0],
                        True,
                    )
                )
                flows, coverage = self.flows(
                    [
                        ("invoke", USAGE, [7, 2, 3, 4, 5], False),
                        ("result", 5),
                        *steps[:6],
                        call,
                        *steps[6:],
                        *transmission(),
                        0x0E,
                    ]
                )
                self.assertFalse(flows)
                self.assertTrue(any(item["status"] == "PARTIAL" for item in coverage))


if __name__ == "__main__":
    unittest.main()
