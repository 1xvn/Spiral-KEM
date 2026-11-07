"""Pure-stdlib gates for independently observed TLS lifecycle results."""
import json
import unittest

from protocol_rust.lifecycle.tls_peer import fragmented_parts, parse_report


def report(*, clean):
    value = {"status":"passed" if clean else "failed",
             "kem":{"live_keys":0,"executed_jobs":2,"rejected_jobs":0}}
    if clean:
        value.update(auth_key_closed=True, admission_released=True)
    return value


class PeerEvidenceGates(unittest.TestCase):
    def test_fragments_reconstruct_record_and_split_header_and_tag(self):
        raw = bytes(range(256)) * 65
        parts = fragmented_parts(raw)
        self.assertEqual(b"".join(parts), raw)
        self.assertGreater(len(parts), 2)
        self.assertEqual([len(p) for p in parts[:4]], [1, 2, 7, 29])
        self.assertTrue(all(parts))
        self.assertEqual(fragmented_parts(b""), [])

    def test_invalid_fragment_size_cannot_loop_forever(self):
        for sizes in ((), (0,), (-1,), (True,), (1.0,)):
            with self.assertRaises(ValueError):
                fragmented_parts(b"test", sizes)

    def test_clean_requires_exit_and_observed_cleanup(self):
        value = report(clean=True)
        self.assertEqual(parse_report(json.dumps(value), "", 0, clean=True), (value, None))
        for changed, stderr, code in (({**value,"auth_key_closed":False},"",0),
                                      ({**value,"admission_released":False},"",0),
                                      (value,"Error: Closed\n",1), (value,"warning",0)):
            with self.assertRaises(AssertionError):
                parse_report(json.dumps(changed), stderr, code, clean=True)

    def test_negative_requires_nonzero_and_exact_error_label(self):
        value = report(clean=False)
        self.assertEqual(parse_report(json.dumps(value), "Error: Closed\n", 1, clean=False),
                         (value,"Closed"))
        for stderr, code in (("",1), ("Error: Closed\nError: Deadline\n",1),
                             ("Error: Closed\n",0)):
            with self.assertRaises(AssertionError):
                parse_report(json.dumps(value), stderr, code, clean=False)

    def test_missing_or_live_native_key_evidence_cannot_pass(self):
        value = report(clean=False)
        for changed in ({**value,"kem":{}}, {**value,"kem":{"live_keys":1,"executed_jobs":2}},
                        {**value,"kem":{"live_keys":False,"executed_jobs":2}},
                        {**value,"kem":{"live_keys":0,"executed_jobs":1}}):
            with self.assertRaises(AssertionError):
                parse_report(json.dumps(changed), "Error: Closed\n", 1, clean=False)

    def test_extra_final_output_cannot_hide_a_failed_report(self):
        value = report(clean=False)
        with self.assertRaises(AssertionError):
            parse_report(json.dumps(value)+"\n"+json.dumps(value), "Error: Closed\n", 1, clean=False)

    def test_sanitizer_and_panic_are_not_expected_connection_rejections(self):
        value=report(clean=False)
        for diagnostic in ('ERROR: AddressSanitizer: heap-buffer-overflow',
                           'SUMMARY: LeakSanitizer: detected memory leaks',
                           "thread 'main' panicked at src/channel.rs:1:1"):
            with self.assertRaises(AssertionError):
                parse_report(json.dumps(value),'Error: Closed\n'+diagnostic,1,clean=False)


if __name__ == "__main__":
    unittest.main()
