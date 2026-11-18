"""Evidence-based regressions; no sockets, keys or waiting."""
from pathlib import Path
import unittest

from isolation_contract import validate
from load_campaign import strict_json
from verify_isolation import read_archive, verify

ARCHIVE = Path(__file__).resolve().parents[1]/'evidence/session_isolation_20261118/local-linux.tar.gz'


class IsolationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = read_archive(ARCHIVE)

    def journal(self, case='release'):
        rows = [strict_json(l) for l in self.files[f'{case}/controller.jsonl'].splitlines()]
        exits = strict_json(self.files[f'{case}/result.json'])['exits']
        return rows, exits

    def test_three_original_runs_replay(self):
        self.assertEqual([r['case'] for r in verify(self.files)],['hold','release','timeout'])

    def test_raw_disagreement(self):
        tempered = dict(self.files)
        tempered['release/2.jsonl'] = tempered['release/1.jsonl']
        with self.assertRaisesRegex(ValueError,'raw stream mismatch'):
            verify(tempered)

    def test_wrong_authenticated_lane_or_sequence(self):
        rows,exits = self.journal()
        first = next(r for r in rows if r['origin']=='1' and r['data'].get('event')=='verified')
        other = next(r for r in rows if r['origin']=='2' and r['data'].get('event')=='verified')
        for key in ('session_id','transcript_hash','binding_hash','lane','sequence'):
            original = first['data'][key]
            first['data'][key] = other['data'][key] if key!='sequence' else original+1
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate('release',rows,exits)
            first['data'][key] = original

    def test_progress_after_resume_cannot_prove_overlap(self):
        rows, exits = self.journal()
        i = next(i for i,r in enumerate(rows) if r['data'].get('event')=='gate_stall_confirmed')
        j = next(i for i,r in enumerate(rows) if r['data'].get('event')=='overlap_verified')
        rows[i+1]['origin'],rows[i+1]['data'] = 'control',rows[j]['data']
        del rows[j]
        with self.assertRaises(ValueError):
            validate('release',rows,exits)

    def test_no_real_socket_stall(self):
        rows,exits = self.journal()
        event = next(r['data']['payload'] for r in rows if r['data'].get('payload',{}).get('event')=='wire_stalled')
        event['wire_snapshot']['write_pending'] = False
        with self.assertRaises(ValueError):
            validate('release',rows,exits)

    def test_replacement_without_reclaimed_key(self):
        rows,exits = self.journal()
        r = next(r for r in rows if r['data'].get('payload',{}).get('event')=='reclaimed')
        r['data']['payload']['live_keys'] = 1
        with self.assertRaises(ValueError):
            validate('release',rows,exits)

    def test_gap_exceeding_budget(self):
        rows,exits = self.journal()
        start = next(i for i,r in enumerate(rows) if r['data'].get('event')=='gate_stall_confirmed')
        for row in rows[start:]:
            row['ns'] += 6_000_000_000
        with self.assertRaises(ValueError):
            validate('release',rows,exits)

    def test_watchdog_exit_or_missing_deadline(self):
        rows,exits = self.journal('timeout')
        with self.assertRaises(ValueError):
            validate('timeout',rows,dict(exits,gate=124))
        rows = [r for r in rows if r['data'].get('payload',{}).get('event')!='wire_timeout']
        with self.assertRaises(ValueError):
            validate('timeout',rows,exits)

    def test_remote_receipt_required_for_operator_scope(self):
        rows,exits = self.journal()
        with self.assertRaises(ValueError):
            validate('release',rows,exits,{})


if __name__ == '__main__':
    unittest.main()
