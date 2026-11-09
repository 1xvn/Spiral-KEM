#!/usr/bin/env python3
"""Focused receipt-parser regressions; no uploaded code or crypto is run."""
import importlib.util
import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('receipt_reviewer', HERE / 'review_uploaded_results.py')
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)


class ReceiptParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.local, _ = reviewer.hashed_members(HERE / reviewer.LOCAL, reviewer.LOCAL_SHA256)
        cls.rust = cls.local['logs/rust-library-tests.stdout.log'].decode()
        cls.suites = []
        for name, class_name in (('key-operations', 'KeyOperations'), ('key-recovery', 'KeyRecovery')):
            text = cls.local['logs/' + name + '.stderr.log'].decode()
            # Fixture identities come from the receipt, independently of parser output.
            names = {line.split(' ', 1)[0] for line in text.splitlines() if line.startswith('test_')}
            cls.suites.append((text, class_name, names))

    def test_actual_reference_logs_are_accepted(self):
        rows = reviewer.rust_rows(self.rust)
        self.assertEqual((len(rows), list(rows.values()).count('ok'), list(rows.values()).count('ignored')), (99, 94, 5))
        for text, class_name, expected in self.suites:
            self.assertEqual(reviewer.key_test_rows(text, class_name, expected), sorted(expected))

    def test_duplicate_rust_identity_is_rejected(self):
        rows = [line for line in self.rust.splitlines() if line.startswith('test ')]
        with self.assertRaises(ValueError):
            reviewer.rust_rows(self.rust.replace(rows[1], rows[0], 1))

    def test_failed_or_extra_rust_status_is_rejected(self):
        for text in (self.rust.replace(' ... ok\n', ' ... FAILED\n', 1),
                     self.rust.replace('\ntest result:', '\ntest forged ... ok\n\ntest result:', 1)):
            with self.subTest(text=text[-150:]), self.assertRaises(ValueError):
                reviewer.rust_rows(text)

    def test_rust_summary_and_trailing_status_are_rejected(self):
        for text in (self.rust.replace('0 filtered out;', '1 filtered out;'),
                     self.rust + 'test forged ... FAILED\n', self.rust + 'FAILED\n'):
            with self.subTest(text=text[-150:]), self.assertRaises(ValueError):
                reviewer.rust_rows(text)

    def test_duplicate_unittest_identity_is_rejected(self):
        for text, class_name, expected in self.suites:
            lines = text.splitlines()
            with self.subTest(class_name=class_name), self.assertRaises(ValueError):
                reviewer.key_test_rows(text.replace(lines[1], lines[0], 1), class_name, expected)

    def test_failed_error_skipped_and_unexpected_status_are_rejected(self):
        for text, class_name, expected in self.suites:
            for status in ('FAIL', 'ERROR', "skipped 'not supported'", 'expected failure', 'unexpected success'):
                with self.subTest(class_name=class_name, status=status), self.assertRaises(ValueError):
                    reviewer.key_test_rows(text.replace(' ... ok\n', ' ... ' + status + '\n', 1), class_name, expected)

    def test_extra_unittest_status_and_trailing_ok_are_rejected(self):
        for text, class_name, expected in self.suites:
            first = text.splitlines()[0] + '\n'
            for changed in (text + first, text + 'FAIL\nOK\n', text + 'OK\n', first + text):
                with self.subTest(class_name=class_name, suffix=changed[-100:]), self.assertRaises(ValueError):
                    reviewer.key_test_rows(changed, class_name, expected)

    def test_unittest_missing_or_wrong_method_and_wrong_summary_are_rejected(self):
        for text, class_name, expected in self.suites:
            first = text.splitlines()[0] + '\n'
            for changed in (text.removeprefix(first), text.replace(first.split(' ')[0], 'test_forged', 1),
                            text.replace('Ran ' + str(len(expected)) + ' tests', 'Ran 1 tests')):
                with self.subTest(class_name=class_name), self.assertRaises(ValueError):
                    reviewer.key_test_rows(changed, class_name, expected)

    def test_duplicate_json_keys_and_nonfinite_values_are_rejected(self):
        for raw in ('{"status":"passed","status":"failed"}', '{"elapsed":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                reviewer.decode(raw)

    def test_failed_rerun_invalidates_previous_accepted_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            summary = output / 'platform-summary.json'
            summary.write_text('{"status":"accepted"}\n')
            args = argparse.Namespace(oci=Path('unused'), wsl=Path('unused'), output_dir=output)
            with patch.object(argparse.ArgumentParser, 'parse_args', return_value=args), \
                    patch.object(reviewer, 'write_reviews', side_effect=ValueError('invalid receipt')):
                with self.assertRaisesRegex(ValueError, 'invalid receipt'):
                    reviewer.main()
            result = json.loads(summary.read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertFalse(result['platform_key_recovery_validation_complete'])
            self.assertFalse(any(result['gates'].values()))


if __name__ == '__main__':
    unittest.main()
