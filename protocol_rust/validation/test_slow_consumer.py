"""Operational bounds and fresh-session contracts; no SSH or long workloads."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cross_host_smoke as base
import slow_consumer as runner


class OperatorContracts(unittest.TestCase):
    def test_server_watchdog_allows_real_idle_expiry(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder);state=home/base.STATE;state.mkdir()
            metadata={'source':{'files':{}},'runner_sha256':'a','binary_sha256':'b'}
            (state/'provenance.json').write_text(json.dumps(metadata))
            with patch.object(Path,'home',return_value=home),patch.object(base,'source',return_value=metadata), \
                 patch.object(base.os,'execvp') as execute:
                for case in runner.CASES:
                    base.serve(backpressure_case=case)
                    command=execute.call_args.args[1]
                    self.assertEqual(command[:3],['timeout','--kill-after=5s','90s'])
                    self.assertEqual(command[-4:],['--backpressure-case',case,'--payload','1024'])
                base.serve()
                self.assertEqual(execute.call_args.args[1][2],'60s')

    def test_diagnostic_modes_cannot_overlap(self):
        with self.assertRaises(ValueError):base.serve(3,'timeout')
        with self.assertRaises(ValueError):base.server_ssh_command(['ssh'],'test',3,'timeout')

    def test_remote_command_rejects_untrusted_case_text(self):
        with self.assertRaises(ValueError):base.server_ssh_command(['ssh'],'test',backpressure_case='timeout; id')

    def test_fresh_recovery_rejects_reused_binding(self):
        pressure={name:'a' for name in runner.IDENTIFIERS}
        recovered={'client':{'sessions':[{name:'b' for name in runner.IDENTIFIERS}]}}
        results=[{'endpoint_events':{'client':[dict(event='pressure_saturated',**pressure)]}}]
        self.assertTrue(runner.recovery_fresh(results,recovered))
        recovered['client']['sessions'][0]['binding_hash']='a'
        self.assertFalse(runner.recovery_fresh(results,recovered))

    def test_repeated_pressure_sessions_are_rejected(self):
        pressure={name:'a' for name in runner.IDENTIFIERS}
        result={'endpoint_events':{'client':[dict(event='pressure_saturated',**pressure)]}}
        recovered={'client':{'sessions':[{name:'b' for name in runner.IDENTIFIERS}]}}
        with self.assertRaises(ValueError):runner.recovery_fresh([result,result],recovered)


if __name__=='__main__':unittest.main()
