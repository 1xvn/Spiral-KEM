"""Regression checks for rejecting misleading status lines in receipt logs."""
import ast
import importlib.util
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('receipt_review', HERE / 'review_uploaded_results.py')
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


class ReceiptStatusRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.items = review.archive_files(HERE / 'Spiral-key-ops-oci-aarch64-20261109T130652Z-rv8uq0i0.tar.gz')
        cls.rust = cls.items['logs/rust-library-tests.stdout.log'].decode()
        cls.key = cls.items['logs/key-operations.stderr.log'].decode()
        tree = ast.parse((review.REPO / 'protocol_rust/key_ops_tests.py').read_text())
        methods = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'KeyOperations')
        cls.expected = {node.name for node in methods.body
                        if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}

    def test_real_receipt_statuses_pass(self):
        self.assertEqual(len(review.rust_rows(self.rust)), 86)
        review.key_test_rows(self.key, self.expected)

    def test_duplicate_and_failed_rust_statuses_are_rejected(self):
        names = re.findall(r'^test (\S+) \.\.\. ok$', self.rust, re.MULTILINE)
        changes = (self.rust + 'test injected::case ... FAILED\n',
                   self.rust.replace('test ' + names[1] + ' ... ok', 'test ' + names[0] + ' ... ok', 1),
                   self.rust.replace('test ' + names[0] + ' ... ok', 'test ' + names[0] + ' ... FAILED', 1))
        for changed in changes:
            with self.subTest(log=changed[-100:]), self.assertRaises(ValueError):
                review.rust_rows(changed)

    def test_failed_skipped_duplicate_and_trailing_key_statuses_are_rejected(self):
        names = re.findall(r'^(test_\w+) \(', self.key, re.MULTILINE)
        row = names[0] + ' (__main__.KeyOperations.' + names[0] + ') ... '
        second = names[1] + ' (__main__.KeyOperations.' + names[1] + ') ... '
        changes = [self.key.replace(row + 'ok', row + status, 1)
                   for status in ('FAIL', 'ERROR', "skipped 'disabled'")]
        changes.extend((self.key.replace(second + 'ok', row + 'ok', 1),
                        self.key + 'test_extra (__main__.Other.test_extra) ... ERROR\n',
                        self.key + 'unexpected trailing output\n'))
        for changed in changes:
            with self.subTest(log=changed[-100:]), self.assertRaises(ValueError):
                review.key_test_rows(changed, self.expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
