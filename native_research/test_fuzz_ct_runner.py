"""Evidence gates and portable packaging for the native ciphertext campaign."""
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from native_research import ct_oracle
from native_research.fuzz_ct import clean_exit, compare_record, make_bundle


class RunnerTests(unittest.TestCase):
    def test_sanitizer_diagnostics_cannot_pass_even_with_zero_exit(self):
        self.assertTrue(clean_exit(0, '#2000 DONE cov: 73 ft: 79'))
        for message in ('ERROR: AddressSanitizer: heap-buffer-overflow',
                        'SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior',
                        'ERROR: LeakSanitizer: detected memory leaks',
                        'runtime error: index out of bounds',
                        'LeakSanitizer has encountered a fatal error',
                        'Assertion `status == SP_OK` failed',
                        'SUMMARY: libFuzzer: deadly signal'):
            self.assertFalse(clean_exit(0, message))
        for code in (1, 23, 77, -9, None):
            self.assertFalse(clean_exit(code, ''))

    def test_missing_swapped_or_wrong_native_result_is_rejected(self):
        data = ct_oracle.fixture()['ct']
        expected = {'status':0, 'ss':ct_oracle.fixture()['ss']}
        good = {'sha256':hashlib.sha256(data).hexdigest(), 'status':0,
                'canonical':True, 'shared_secret_hex':expected['ss'].hex()}
        self.assertTrue(compare_record(good, data, expected))
        cases = ({}, {**good, 'sha256':'0'*64}, {**good, 'status':1},
                 {**good, 'status':False}, {**good, 'canonical':1},
                 {**good, 'canonical':False}, {**good, 'shared_secret_hex':'a5'*32})
        for record in cases:
            self.assertFalse(compare_record(record, data, expected))
        for field in good:
            self.assertFalse(compare_record({k:v for k,v in good.items() if k!=field}, data, expected))

    def test_archive_contains_result_and_public_inputs_without_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out = root/'run'; out.mkdir()
            (out/'build').mkdir(); (out/'corpus').mkdir()
            (out/'result.json').write_text(json.dumps({'status':'failed','error':'example'}))
            (out/'corpus/public-input').write_bytes(b'input')
            (out/'build/fuzz-ct').write_bytes(b'binary')
            archive = root/'run.tar.gz'
            make_bundle(out, archive)
            with tarfile.open(archive, 'r:gz') as packed:
                self.assertIn('run/result.json', packed.getnames())
                self.assertIn('run/corpus/public-input', packed.getnames())
                self.assertFalse(any('/build' in name for name in packed.getnames()))
            saved = archive.read_bytes()
            with self.assertRaises(FileExistsError):
                make_bundle(out, archive)
            self.assertEqual(archive.read_bytes(), saved)

    def test_incomplete_or_linked_archive_is_never_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out = root/'run'; out.mkdir(); archive = root/'run.tar.gz'
            with self.assertRaises(RuntimeError):
                make_bundle(out, archive)
            self.assertFalse(archive.exists())
            (out/'result.json').write_text('{}')
            (out/'unexpected').symlink_to(out/'result.json')
            with self.assertRaises(RuntimeError):
                make_bundle(out, archive)
            self.assertFalse(archive.exists())
            self.assertFalse(list(root.glob('*.partial')))


if __name__ == '__main__':
    unittest.main()
