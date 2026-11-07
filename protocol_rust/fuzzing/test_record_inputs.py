"""Independent state, boundary, corruption, and corpus checks for record replay."""
import unittest

from protocol_rust.fuzzing import record_inputs as records


def program(*commands, scenario=0, role=0):
    return bytes([scenario, role]) + b"".join(bytes(command) for command in commands)


def evaluate(*commands, scenario=0, role=0):
    return records.expected("record", program(*commands, scenario=scenario, role=role))


class StateTrace(unittest.TestCase):
    def test_data_delivery_and_authenticated_close_both_roles(self):
        for role in (0, 1):
            trace = evaluate((0, 3, 7, 1), (2, 0, 0, 0),
                             (1, 2, 0, 0), (2, 1, 0, 0), role=role)
            self.assertTrue(trace["accepted"])
            data_send, data_receive, close_send, close_receive = trace["steps"]
            self.assertEqual(data_send["result"]["length"], 40 + 31 + 16)
            self.assertEqual(data_receive["result"]["kind"], 16)
            self.assertEqual(data_receive["result"]["length"], 31)
            self.assertEqual(close_send["result"]["length"], 57)
            self.assertEqual(close_receive["result"]["kind"], 17)
            for side in ("tx", "rx"):
                self.assertEqual(close_receive[side], {"sequence": 2, "bytes": 31,
                    "closed": True, "key_live": False})

    def test_replay_and_out_of_order_poison_receive_half(self):
        for commands in (
            ((0, 1, 0, 0), (2, 0, 0, 0), (2, 0, 0, 0), (4, 0, 1, 0)),
            ((0, 1, 0, 0), (0, 1, 1, 0), (2, 1, 0, 0), (2, 0, 0, 0)),
        ):
            trace = evaluate(*commands)
            rejected, retry = trace["steps"][-2:]
            self.assertEqual(rejected["result"], {"ok": False, "error": "Input"})
            self.assertEqual(retry["result"], {"ok": False, "error": "Closed"})
            self.assertEqual(rejected["rx"], retry["rx"])
            self.assertTrue(retry["rx"]["closed"])
            self.assertFalse(retry["rx"]["key_live"])

    def test_authentication_failure_is_terminal_without_counter_advance(self):
        trace = evaluate((4, 32, 1, 0), (4, 0, 1, 0), (0, 1, 0, 0))
        bad, retry, tx_still_independent = trace["steps"]
        self.assertEqual(bad["result"], {"ok": False, "error": "Authentication"})
        self.assertEqual(bad["rx"], {"sequence": 0, "bytes": 0,
                                    "closed": True, "key_live": False})
        self.assertEqual(retry["result"], {"ok": False, "error": "Closed"})
        self.assertTrue(tx_still_independent["result"]["ok"])

    def test_invalid_data_releases_key_but_matches_low_level_closed_flag(self):
        for size in (0, 6):
            trace = evaluate((0, size, 0, 0), (0, 1, 0, 0), (1, 0, 0, 0))
            first, data_retry, close_retry = trace["steps"]
            self.assertEqual(first["result"], {"ok": False, "error": "Input"})
            self.assertEqual(first["tx"], {"sequence": 0, "bytes": 0,
                                          "closed": False, "key_live": False})
            for step in (data_retry, close_retry):
                self.assertEqual(step["result"], {"ok": False, "error": "Closed"})

    def test_invalid_close_reason_precedes_closed_check_and_does_not_poison(self):
        trace = evaluate((1, 3, 0, 0), (1, 0, 0, 0),
                         (1, 255, 0, 0), (1, 0, 0, 0))
        first, close, invalid_after_close, valid_after_close = trace["steps"]
        self.assertEqual(first["result"], {"ok": False, "error": "Input"})
        self.assertEqual(first["tx"], trace["initial"]["tx"])
        self.assertTrue(close["result"]["ok"])
        self.assertEqual(invalid_after_close["result"], {"ok": False, "error": "Input"})
        self.assertEqual(valid_after_close["result"], {"ok": False, "error": "Closed"})
        self.assertEqual(close["tx"], valid_after_close["tx"])

    def test_authenticated_invalid_close_reason_poisoned_after_authentication(self):
        trace = evaluate((4, 1, 0, 3), (4, 0, 1, 0))
        self.assertEqual(trace["steps"][0]["result"], {"ok": False, "error": "Input"})
        self.assertEqual(trace["steps"][1]["result"], {"ok": False, "error": "Closed"})
        self.assertEqual(trace["steps"][0]["rx"]["sequence"], 0)

    def test_reserved_close_counter_and_exhausted_counter(self):
        trace = evaluate((0, 1, 0, 0), (1, 2, 0, 0), (2, 0, 0, 0), scenario=2)
        self.assertEqual(trace["steps"][0]["result"], {"ok": False, "error": "Limit2"})
        self.assertTrue(trace["steps"][0]["tx"]["key_live"])
        self.assertTrue(trace["steps"][1]["result"]["ok"])
        self.assertTrue(trace["steps"][2]["result"]["ok"])
        self.assertEqual(trace["steps"][2]["rx"]["sequence"], records.MAX_RECORDS)
        exhausted = evaluate((1, 0, 0, 0), (1, 0, 0, 0), scenario=3)
        self.assertEqual(exhausted["steps"][0]["result"], {"ok": False, "error": "Input"})
        self.assertEqual(exhausted["steps"][1]["result"], {"ok": False, "error": "Closed"})

    def test_last_data_then_final_close_preserves_exact_counters(self):
        trace = evaluate((0, 1, 1, 1), (2, 0, 0, 0), (0, 1, 0, 0),
                         (1, 0, 0, 0), (2, 1, 0, 0), scenario=1)
        self.assertEqual(trace["steps"][2]["result"], {"ok": False, "error": "Limit2"})
        final = trace["steps"][-1]
        for side in ("tx", "rx"):
            self.assertEqual(final[side], {"sequence": records.MAX_RECORDS, "bytes": 1,
                                          "closed": True, "key_live": False})

    def test_byte_limit_keeps_tx_close_available_but_rx_limit_is_terminal(self):
        trace = evaluate((0, 1, 0, 0), (2, 0, 0, 0), (0, 1, 0, 0),
                         (1, 0, 0, 0), (2, 1, 0, 0), scenario=4)
        self.assertEqual(trace["steps"][2]["result"], {"ok": False, "error": "Limit2"})
        self.assertTrue(trace["steps"][3]["result"]["ok"])
        self.assertTrue(trace["steps"][4]["result"]["ok"])
        self.assertEqual(trace["steps"][-1]["rx"]["bytes"], records.MAX_BYTES)
        rejected = evaluate((4, 0, 1, 0), (4, 1, 0, 0), scenario=5)
        self.assertEqual(rejected["steps"][0]["result"], {"ok": False, "error": "Limit2"})
        self.assertEqual(rejected["steps"][1]["result"], {"ok": False, "error": "Closed"})

    def test_maximum_size_data_and_exact_large_byte_boundary(self):
        trace = evaluate((0, 5, 254, 7), (2, 0, 0, 0))
        self.assertTrue(trace["accepted"])
        self.assertEqual(trace["steps"][0]["result"]["length"], 16440)
        self.assertEqual(trace["steps"][1]["result"]["length"], 16384)
        boundary = evaluate((0, 4, 0, 1), (2, 0, 0, 0), (0, 1, 0, 0), scenario=6)
        self.assertEqual(boundary["steps"][1]["rx"]["bytes"], records.MAX_BYTES)
        self.assertEqual(boundary["steps"][2]["result"], {"ok": False, "error": "Limit2"})

    def test_all_stored_mutations_reject_and_poison(self):
        for mutation in range(8):
            trace = evaluate((0, 3, 42, 1), (3, 0, mutation, 40), (2, 0, 0, 0))
            self.assertFalse(trace["steps"][1]["result"]["ok"])
            self.assertIn(trace["steps"][1]["result"]["error"], ("Input", "Authentication"))
            self.assertEqual(trace["steps"][2]["result"], {"ok": False, "error": "Closed"})

    def test_crafted_metadata_and_counter_rejected_even_with_correct_tags(self):
        for choice in (2, 6, 8, 16):
            trace = evaluate((4, choice, 1, 0))
            self.assertEqual(trace["steps"][0]["result"], {"ok": False, "error": "Input"})
        # Saturating previous-sequence selection at zero is intentionally valid.
        self.assertTrue(evaluate((4, 4, 1, 0))["accepted"])


class GrammarAndCorpus(unittest.TestCase):
    def test_partial_commands_and_overlong_tail_have_explicit_finite_semantics(self):
        for data in (b"", b"\0", b"\0\0", b"\0\0\x01", b"\0\0\1\2\3"):
            self.assertEqual(records.expected("record", data)["steps"], [])
        maximum = program(*[(1, 255, 0, 0)] * 64)
        self.assertEqual(len(maximum), 258)
        self.assertEqual(records.expected("record", maximum),
                         records.expected("record", maximum + b"ignored"))
        self.assertEqual(len(records.expected("record", maximum)["steps"]), 64)

    def test_selector_normalization_and_unknown_target(self):
        data = bytes([255, 255]) + bytes([6, 1, 7, 3])
        result = records.expected("record", data)
        self.assertEqual(result["scenario"], 255 % 7)
        self.assertEqual(result["role"], 1)
        self.assertEqual(result["steps"][0]["op"], "data")
        with self.assertRaises(ValueError):
            records.expected("frame", b"")
        with self.assertRaises(ValueError):
            records.expected("record", bytearray())

    def test_seeds_are_deterministic_unique_bounded_and_cover_result_classes(self):
        first = records.seeds()
        self.assertEqual(first, records.seeds())
        self.assertEqual(set(first), {"record"})
        corpus = first["record"]
        self.assertEqual(len(corpus), len(set(corpus)))
        self.assertTrue(all(type(data) is bytes and len(data) <= 258 for data in corpus))
        outcomes = [records.expected("record", data) for data in corpus]
        self.assertEqual({outcome["accepted"] for outcome in outcomes}, {True, False})
        self.assertEqual({outcome["scenario"] for outcome in outcomes}, set(range(7)))
        self.assertEqual({outcome["role"] for outcome in outcomes}, {0, 1})
        self.assertEqual({step["op"] for outcome in outcomes for step in outcome["steps"]},
                         {"data", "close", "deliver", "mutate", "craft", "raw"})
        self.assertEqual({step["result"]["error"] for outcome in outcomes for step in outcome["steps"]
                          if not step["result"]["ok"]},
                         {"Input", "Closed", "Authentication", "Limit2"})


if __name__ == "__main__":
    unittest.main()
