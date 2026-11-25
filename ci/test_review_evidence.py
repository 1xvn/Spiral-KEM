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

    def test_tls_per_case_reasons_bindings_and_cleanup(self):
        from copy import deepcopy
        from evidence import contract, tls_observations
        # Public control convention. The real endpoints run in functional CI.
        rows = []
        next_sid = 0
        paired = {}
        for scenario, specs in contract('tls_contract').items():
            for spec in specs:
                role, reason = spec['role'], spec['reason']
                report = {'status': 'failed' if reason else 'passed',
                          'kem': {'live_keys': 0, 'rejected_jobs': 0, 'executed_jobs': spec['jobs']}}
                if not reason:
                    sessions = []
                    payload = spec['variant'].get('payload')
                    for index, count in enumerate(spec['messages']):
                        next_sid += 1
                        sid = f'{next_sid:032x}'
                        if payload and role == 'client':
                            paired[payload, index] = sid
                        elif payload:
                            sid = paired[payload, index]
                        sessions.append(dict(session_id=sid, authenticated_close=True, messages=count,
                                             payload_bytes=payload, binding_hash='a'*64, transcript_hash='b'*64))
                    report.update(role=role, sessions=sessions, connections=len(sessions))
                    if role == 'server':
                        report.update(auth_key_closed=True, admission_released=True)
                rows.append(dict(scenario=scenario, role=role, exit=1 if reason else 0,
                                 variant=spec['variant'], reason=f'Error: {reason}\n' if reason else '',
                                 report=report))
        tls_observations({'observations': rows})
        for mutation in ('missing', 'wrong_reason', 'live_key', 'missing_close', 'wrong_binding'):
            altered = deepcopy(rows)
            if mutation == 'missing':
                altered.pop()
            elif mutation == 'wrong_reason':
                next(r for r in altered if r['exit'])['reason'] = 'Error: Deadline\n'
            elif mutation == 'live_key':
                altered[0]['report']['kem']['live_keys'] = 1
            elif mutation == 'missing_close':
                next(r for r in altered if not r['exit'])['report']['sessions'][0]['authenticated_close'] = False
            else:
                next(r for r in altered if r['variant'].get('payload'))['report']['sessions'][0]['binding_hash'] = 'c'*64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                tls_observations({'observations': altered})

    def test_load_phase_clock_progress_closes_and_resource_trace(self):
        import sys
        from copy import deepcopy
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protocol_rust/validation'))
        from load_readback import readback
        from load_campaign import ResourceSummary
        from test_load_campaign import completed_report

        def lines(rows):
            return [(json.dumps(row) + '\n').encode() for row in rows]

        n, duration, payload = 4, 10, 64
        kem = dict(live_keys=0, executed_jobs=30, rejected_jobs=0)
        final = dict(completed_report(n), event='final', requested_duration_seconds=duration,
                     actual_elapsed_seconds=21, soak_elapsed_seconds=10.1, traffic_epoch_elapsed_seconds=10,
                     completed_epochs=1, total_messages=12, authenticated_pairs_total=10,
                     authenticated_pair_closes=10, successful_endpoint_handshakes=20,
                     kem=kem, echoed_bytes=768, bidirectional_payload_bytes=1536, admission_rejected=2)
        def sample(at, messages, live):
            return dict(event='sample', soak_elapsed_seconds=at, total_messages=messages, active=n if live else 0,
                        pending=0, expected_established_connections=n if live else 0,
                        completed_epochs=0 if live else 1, echoed_bytes=messages*payload,
                        authenticated_pairs_total=10, admission_rejected=2, kem=kem)
        events = [
            dict(event='start', connections=n, duration_seconds=duration, payload_bytes=payload,
                 interval_ms=50, resource_baseline=final['resource_baseline']),
            dict(event='limit_case', id='per_ip_four_then_fifth_rejected_and_refill_recovered',
                 status='passed', rejected=1, authenticated_pairs=5),
            dict(event='limit_case', id='pending_32_then_33rd_rejected_idle_tls_timeout_and_recovery',
                 status='passed', rejected=1, pending_peak=32),
            dict(event='rotation_started', completed_epochs=0, initial=True),
            dict(event='rotation_ready', active=n, expected_established_connections=n, pending=0,
                 completed_epochs=0, initial=True, authenticated_pairs_total=10),
            dict(event='soak_started', duration_seconds=duration, active=n),
            dict(event='traffic_started', completed_epochs=0, expected_established_connections=n, soak_elapsed_seconds=0),
            sample(1, 4, True), sample(9, 12, True),
            dict(event='closing_started', completed_epochs=0, soak_elapsed_seconds=10),
            sample(10.1, 12, False), final,
        ]
        resources = [dict(elapsed_seconds=i, rss_kib=100, peak_rss_kib=101, anonymous_rss_kib=10,
                          file_rss_kib=90, fd_count=4, threads=2, major_faults=0, minor_faults=i,
                          cpu_seconds=i/10) for i in range(22)]
        summary = ResourceSummary()
        for row in resources:
            summary.add(row)
        result = dict(status='passed', source_unchanged=True, binary_unchanged=True,
                      requested_duration_seconds=duration, requested_connections=n, payload_bytes=payload,
                      interval_ms=50, collector_monotonic_elapsed_seconds=21.1, probe_exit_code=0,
                      probe_final=final, resource_samples=len(resources), resources=summary.report(),
                      resource_limits=dict(fds=20, threads=20, rss_mib=10))
        readback(result, lines(events), lines(resources), b'')
        for mutation in ('final_only', 'clock', 'stage', 'progress', 'closes', 'resources', 'gap'):
            r, e, trace = deepcopy((result, events, resources))
            if mutation == 'final_only':
                e = e[-1:]
            elif mutation == 'clock':
                r['collector_monotonic_elapsed_seconds'] = .014
            elif mutation == 'stage':
                del e[4]
            elif mutation == 'progress':
                for row in e[7:9]:
                    row['total_messages'] = 0
            elif mutation == 'closes':
                e[-1]['authenticated_pair_closes'] = 9
            elif mutation == 'resources':
                trace.pop()
            else:
                trace[7]['elapsed_seconds'] = 3
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                readback(r, lines(e), lines(trace), b'')
