"""Gate authorization and fixed-command contracts; no TLS or long workload."""
from copy import deepcopy
import unittest
from unittest.mock import patch

import wire_gate as gate


def ready(case='release'):
    return {'event':'wire_ready','role':'server','case':case,'baseline_echoes':3,
            'bulk_messages':1021,'payload_bytes':16384,'session_id':'a'*32,
            'binding_hash':'b'*64,'transcript_hash':'c'*64}


def command(action='pause'):
    return {'action':action,**{name:ready()[name] for name in gate.IDS}}


class GateContracts(unittest.TestCase):
    def test_pause_requires_authenticated_binding(self):
        self.assertEqual(gate.check_command(command(),'release',ready(),False,False,False),'pause')
        with self.assertRaises(ValueError):gate.check_command(command(),'release',None,False,False,False)

    def test_repeat_or_late_pause_is_rejected(self):
        for state in ((True,False,False),(True,True,False),(True,True,True),(False,True,False)):
            with self.subTest(state=state),self.assertRaises(ValueError):
                gate.check_command(command(),'release',ready(),*state)

    def test_resume_requires_positive_stall_in_release_case(self):
        self.assertEqual(gate.check_command(command('resume'),'release',ready(),True,True,False),'resume')
        for state in ((False,False,False),(True,False,False),(True,True,True)):
            with self.subTest(state=state),self.assertRaises(ValueError):
                gate.check_command(command('resume'),'release',ready(),*state)

    def test_timeout_cannot_resume(self):
        with self.assertRaises(ValueError):
            gate.check_command(command('resume'),'timeout',ready('timeout'),True,True,False)

    def test_each_command_binding_component_must_match(self):
        for name in gate.IDS:
            value=command();value[name]='d'*len(value[name])
            with self.subTest(name=name),self.assertRaises(ValueError):
                gate.check_command(value,'release',ready(),False,False,False)

    def test_caller_cannot_supply_process_signal_or_command(self):
        for name,value in (('pid',123),('signal','SIGKILL'),('command','other')):
            with self.subTest(name=name),self.assertRaises(ValueError):
                gate.check_command({**command(),name:value},'release',ready(),False,False,False)

    def test_unknown_action_and_invalid_identifiers_are_rejected(self):
        for action in ('kill','',None,True):
            with self.subTest(action=action),self.assertRaises(ValueError):
                gate.check_command(command(action),'release',ready(),False,False,False)
        for value in ('0'*32,'A'*32,'a'*31,None):
            with self.subTest(value=value),self.assertRaises(ValueError):
                gate.check_command({**command(),'session_id':value},'release',ready(),False,False,False)

    def test_peer_case_role_and_binding_are_required(self):
        for field,value in (('case','timeout'),('role','client'),('session_id','d'*32)):
            event={**ready(),field:value}
            with self.subTest(field=field),self.assertRaises(ValueError):gate.check_bound(event,'release',ready())

    def test_fixed_server_command_changes_only_diagnostic_workload(self):
        original=['spiral-lab','server','--port','39401','--connections','1',
                  '--messages','10','--workers','1','--key','private/key.pem']
        with patch.object(gate.base,'prepared_server_command',side_effect=lambda:deepcopy(original)):
            for case in gate.CASES:
                built=gate.server_command(case)
                self.assertEqual(built[-4:],['--payload','16384','--wire-stall-case',case])
                self.assertEqual(built[built.index('--messages')+1],'1024')
                self.assertEqual(built[built.index('--key')+1],'private/key.pem')
                self.assertEqual(built[built.index('--connections')+1],'1')
        with self.assertRaises(ValueError):gate.server_command('other')


if __name__=='__main__':unittest.main()
