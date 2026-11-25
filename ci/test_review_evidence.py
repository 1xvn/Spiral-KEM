import json
from pathlib import Path
import tempfile
import unittest

from evidence import structured_result
from public_receipt import publish


class ReviewContracts(unittest.TestCase):
    def test_tls_observations_are_required(self):
        metadata = dict(schema='spiral-rust-adversarial/v0.3', tests=35, failures=0, errors=0)
        raw = (json.dumps(metadata) + '\n').encode()
        with self.assertRaises(ValueError):
            structured_result(raw, 35, None, raw, 'rust-tls')

    def test_publication_after_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'functional').mkdir()
            (root / 'functional/interop.json').write_text('PRIVATE-TEST-MARKER')
            public = root / 'public'
            publish('functional', 'failure', root, public)
            self.assertEqual([p.name for p in public.iterdir()], ['receipt.json'])
            self.assertNotIn('PRIVATE-TEST-MARKER', (public / 'receipt.json').read_text())

    def test_names_and_ignored_state_are_bound_to_suite(self):
        from evidence import contract, libtest_result, unittest_result
        names = contract('test_inventory')['client-auth-lab']
        def transcript(cases):
            rows = [f"{n.split('.')[-1]} ({n}) ... ok" for n in cases]
            return ('\n'.join([*rows, '-' * 70, 'Ran 2 tests in 0.01s', 'OK', ''])).encode()
        unittest_result(transcript(names), 2, suite='client-auth-lab')
        with self.assertRaises(ValueError):
            unittest_result(transcript([names[0], 'suite.C.test_unrelated']), 2, suite='client-auth-lab')
        from test_checks import TranscriptContracts
        expected = {'case_a': 'ok', 'case_b': 'ignored'}
        raw = TranscriptContracts.rust_log
        libtest_result(raw, 1, 1, inventory=expected)
        with self.assertRaises(ValueError):
            libtest_result(raw.replace(b'case_a', b'other'), 1, 1, inventory=expected)
        with self.assertRaises(ValueError):
            libtest_result(raw, 1, 1, inventory={'case_a': 'ignored', 'case_b': 'ok'})

    def test_auth_stages_configuration_cleanup_and_stdout(self):
        from evidence import client_auth_rejections
        from copy import deepcopy
        path = Path(__file__).resolve().parents[1] / 'protocol_rust/evidence/client_auth_20261118/connections.json'
        data = json.loads(path.read_bytes())
        # Public legacy fixture plus explicit synthetic terminal reasons.
        errors = {'other-session-record': 'Closed', 'duplicate-record': 'Closed',
                  'missing-spiral-server-pin': 'Transport'}
        for r in data['cases']:
            r['server_stderr'] = '' if r['case'] == 'read-status' else 'Error: ' + errors.get(r['case'], 'Authentication') + '\n'
        self.assertEqual(len(client_auth_rejections(data)), 19)
        for field in ('phase', 'configuration', 'cleanup', 'stdout'):
            case = deepcopy(data)
            row = next(r for r in case['cases'] if r['case'] == 'forbidden-write')
            stages = row['server_stdout_after_listen']
            if field == 'phase':
                stages[:2] = [{'event': 'tls_peer_rejected'}]
            elif field == 'configuration':
                case['configuration'].pop()
            elif field == 'cleanup':
                stages[-2]['drained'] = 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                structured_result(json.dumps(case), 2, None,
                                  b'FAILED\n' if field == 'stdout' else b'', 'client-auth-lab')

    def test_missing_scratch_child_fails(self):
        from evidence import scratch_result, SCRATCH_MATRIX
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            labels = [r[0] for r in SCRATCH_MATRIX]
            stdout = ('\n'.join(labels + [json.dumps(dict(status='passed', tests=23, output=tmp))]) + '\n').encode()
            with self.assertRaises(FileNotFoundError):
                scratch_result(folder, stdout, b'')
            with self.assertRaises(ValueError):
                scratch_result(folder, b'', b'')

    def test_provenance_and_receipt_bind_same_input(self):
        from contextlib import redirect_stdout
        from io import StringIO
        import sys
        from unittest.mock import patch
        import shutil
        import check_memory_result as gate
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source = Path(__file__).resolve().parents[1] / 'protocol_rust/evidence/libtest_memory_20261107'
            shutil.copytree(source, folder, dirs_exist_ok=True)
            path = folder / 'result.json'
            raw = path.read_bytes()
            receipt = folder / 'review.json'
            real_review = gate.review
            def replace_after_read(path, captured):
                path.write_bytes(b'{}\n')
                return real_review(path, captured)
            with patch.object(sys, 'argv', ['gate', str(path), '--verdict', str(receipt)]), \
                 patch.object(gate, 'review', replace_after_read), redirect_stdout(StringIO()):
                self.assertEqual(gate.main(), 1)
            verdict = json.loads(receipt.read_bytes())
            self.assertEqual(verdict['classification'], 'diagnostic_warning')
            self.assertEqual(verdict['input_sha256'], gate.sha(raw))
            data = json.loads(raw)
            data.pop('builds')
            with self.assertRaises((KeyError, ValueError)):
                real_review(path, json.dumps(data).encode())

    def test_publication_rejects_incomplete_success_inventory(self):
        import hashlib
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private = root / 'functional'
            (private / 'scratch-cleanup').mkdir(parents=True)
            commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
            source = json.dumps({'commit': commit}).encode()
            digest = hashlib.sha256(source).hexdigest()
            for phase in ('before', 'after'):
                (private / f'source-{phase}.json').write_bytes(source)
            checks = []
            for name in ('interop.json', 'client-auth-lab.json', 'key-operations.json',
                         'key-recovery.json', 'scratch-cleanup/result.json'):
                (private / name).write_bytes(b'{}')
                checks.append({'name': 'unexpected', 'passed': True, 'structured_file': {
                    'file': name, 'sha256': hashlib.sha256(b'{}').hexdigest()}})
            summary = dict(status='passed', source_before_sha256=digest, source_after_sha256=digest,
                           checks=checks)
            (private / 'result.json').write_text(json.dumps(summary))
            with self.assertRaises(ValueError):
                publish('functional', 'success', root, root / 'public')
