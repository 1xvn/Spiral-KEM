"""Operator command bounds and recovery binding; no long workloads or SSH."""
from pathlib import Path
import unittest
from unittest.mock import patch

import cross_host_smoke as base
import wire_stall as runner


class WireOperatorContracts(unittest.TestCase):
    def test_bounded_client_command_has_no_duplicate_options(self):
        command=runner.wire_client_command(12345,Path('/public'),'release')
        for flag,value in (('--messages','1024'),('--payload','16384'),('--connections','1'),
                           ('--workers','1'),('--wire-stall-case','release')):
            self.assertEqual(command.count(flag),1)
            self.assertEqual(command[command.index(flag)+1],value)

    def test_remote_command_cannot_accept_shell_text_as_case(self):
        with self.assertRaises(ValueError):runner.remote_command(['ssh'],'target','release; id')
        with self.assertRaises(ValueError):runner.wire_client_command(12345,Path('/public'),'all')

    def test_gate_uses_its_own_port_and_outer_watchdog(self):
        command=runner.remote_command(['ssh','-T'],'target','timeout')
        self.assertEqual(command[:3],['ssh','-T','target'])
        self.assertIn('timeout --kill-after=5s 110s',command[-1])
        self.assertIn('wire_gate.py serve --case timeout',command[-1])
        self.assertNotEqual(runner.GATE_PORT,base.REMOTE_PORT)

    def test_invalid_remote_port_is_rejected_before_ssh_spawn(self):
        for value in (0,65536,True,'39402'):
            with self.subTest(value=value),patch.object(base.subprocess,'Popen') as start:
                with self.assertRaises(ValueError):base.start_tunnel(['ssh'],'target',None,remote_port=value)
                start.assert_not_called()

    def test_recovery_must_change_each_bound_identifier(self):
        event={field:'a' for field in runner.IDENTIFIERS}
        results=[{'ready':{'client':event}}]
        recovered={'client':{'sessions':[{field:'b' for field in runner.IDENTIFIERS}]}}
        self.assertTrue(runner.recovery_fresh(results,recovered))
        for field in runner.IDENTIFIERS:
            recovered['client']['sessions'][0][field]='a'
            self.assertFalse(runner.recovery_fresh(results,recovered))
            recovered['client']['sessions'][0][field]='b'

    def test_pressure_cases_cannot_reuse_the_same_session(self):
        event={field:'a' for field in runner.IDENTIFIERS}
        result={'ready':{'client':event}}
        recovered={'client':{'sessions':[{field:'b' for field in runner.IDENTIFIERS}]}}
        with self.assertRaises(ValueError):runner.recovery_fresh([result,result],recovered)


if __name__=='__main__':unittest.main()
