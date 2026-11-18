"""Operator-wrapper contracts only: no subprocesses, signals, TLS or load."""
import hashlib
import contextlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import sys
import unittest
from unittest.mock import patch

import short_operations as operations


class ExpectedFailureContracts(unittest.TestCase):
    def test_each_expected_failure_requires_exact_reason_and_exit(self):
        for kind,reason in operations.FAILURES.items():
            result={'status':'failed','failure':reason,'source_unchanged':True,'binary_unchanged':True}
            with self.subTest(case=kind):
                self.assertTrue(operations.verdict(kind,1,result,{'archive':True,'cleanup':True}))
                self.assertFalse(operations.verdict(kind,0,result,{'archive':True}))
                self.assertFalse(operations.verdict(kind,1,dict(result,failure='unrelated failure'),{'archive':True}))

    def test_cleanup_or_integrity_failure_never_counts_as_expected_success(self):
        result={'status':'failed','failure':operations.FAILURES['interrupt'],
                'source_unchanged':True,'binary_unchanged':True}
        self.assertFalse(operations.verdict('interrupt',1,result,{'cleanup':False}))
        self.assertFalse(operations.verdict('interrupt',1,dict(result,binary_unchanged=False),{'cleanup':True}))

    def test_clock_collection_requires_actual_campaign_success(self):
        result={'status':'passed','source_unchanged':True,'binary_unchanged':True}
        self.assertTrue(operations.verdict('clock',0,result,{'archive':True}))
        self.assertFalse(operations.verdict('clock',1,result,{'archive':True}))
        self.assertFalse(operations.verdict('clock',0,dict(result,status='failed'),{'archive':True}))


class EvidenceAndScopeContracts(unittest.TestCase):
    def test_cancelled_batch_never_starts_later_cases(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); binary=root/'probe'; binary.touch(); output=root/'evidence'
            argv=['short_operations.py','--case','all','--platform','local',
                  '--python',sys.executable,'--binary',str(binary),'--output',str(output)]
            with patch.object(sys,'argv',argv),patch.object(operations,'run_case',
                    side_effect=[{'case':'clock','status':'failed','operator_cancelled':True},
                                 AssertionError('must not start later case')]) as run,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(operations.main(),1)
            self.assertEqual(run.call_count,1)
            self.assertEqual(len(json.loads((output/'summary.json').read_text())['cases']),1)
            self.assertTrue(Path(str(output)+'.tar.gz').is_file())

    def test_emergency_cleanup_does_not_signal_reused_pid(self):
        with patch.object(operations,'matching_probes',side_effect=[[10],[],[]]), \
             patch.object(operations,'probe_identity',side_effect=[(1,10),(2,10)]), \
             patch.object(operations.os,'killpg') as kill:
            self.assertTrue(operations.terminate_case_probes(Path('/probe'),Path('/private')))
        kill.assert_not_called()

    def make_evidence(self,root, clock_trace=False):
        output=root/'campaign'; output.mkdir()
        names={'result.json','source-before.json','source-after.json',
               'probe.stdout.jsonl','probe.stderr.log','resources.jsonl'}
        if clock_trace:
            names.add('clocks.jsonl')
        for name in names:
            (output/name).write_bytes(b'{}\n')
        manifest={name:hashlib.sha256((output/name).read_bytes()).hexdigest() for name in names}
        (output/'SHA256.json').write_text(json.dumps(manifest))
        with tarfile.open(str(output)+'.tar.gz','w:gz') as packed:
            for path in output.iterdir():
                packed.add(path,arcname=output.name+'/'+path.name)
        return output

    def test_evidence_requires_matching_raw_and_archived_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            output=self.make_evidence(Path(folder))
            self.assertTrue(operations.evidence_valid(output))
            (output/'resources.jsonl').write_bytes(b'changed\n')
            self.assertFalse(operations.evidence_valid(output))

    def test_evidence_accepts_and_checks_new_clock_stream(self):
        with tempfile.TemporaryDirectory() as folder:
            output = self.make_evidence(Path(folder), clock_trace=True)
            self.assertTrue(operations.evidence_valid(output))
            (output/'clocks.jsonl').unlink()
            with self.assertRaises(FileNotFoundError):
                operations.evidence_valid(output)

    def test_archive_rejects_extra_and_duplicate_members(self):
        for duplicate in (False,True):
            with self.subTest(duplicate=duplicate),tempfile.TemporaryDirectory() as folder:
                output=self.make_evidence(Path(folder))
                with tarfile.open(str(output)+'.tar.gz','w:gz') as packed:
                    for path in output.iterdir():
                        packed.add(path,arcname=output.name+'/'+path.name)
                    packed.add(output/'result.json',arcname=output.name+('/result.json' if duplicate else '/unexpected.json'))
                self.assertFalse(operations.evidence_valid(output))

    def test_probe_matching_needs_exact_binary_and_private_fixture_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); proc=root/'proc'; proc.mkdir(); binary=root/'load_probe'; private=root/'private'
            commands={10:[str(binary),'--fixture-dir',str(private/'fixture')],
                      11:[str(binary),'--fixture-dir',str(root/'private-other/fixture')],
                      12:[str(root/'other_probe'),'--fixture-dir',str(private/'fixture')]}
            for pid,args in commands.items():
                path=proc/str(pid); path.mkdir()
                (path/'cmdline').write_bytes(b'\0'.join(a.encode() for a in args)+b'\0')
            self.assertEqual(operations.matching_probes(binary,private,proc),[10])


if __name__ == '__main__':
    unittest.main()
