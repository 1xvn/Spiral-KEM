"""Bounded ownership/authorization tests; no TLS, SSH or network campaigns."""
import io
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
import unittest

import crash_supervisor as supervisor


def pending():
    return {'event':'request_pending','role':'server','fault_checkpoint':3,
            'received_messages':4,'echoed_messages':3,'pending_payload_bytes':1024,
            'session_id':'a'*32,'binding_hash':'b'*64,'transcript_hash':'c'*64}


def command():
    value=pending()
    return {'action':'kill',**{name:value[name] for name,_ in supervisor.IDENTIFIERS}}


class CommandContracts(unittest.TestCase):
    def test_matching_owned_checkpoint_authorizes_fixed_action(self):
        supervisor.check_pending(pending())
        supervisor.check_command(command(),pending())

    def test_no_request_or_repeated_request_is_rejected(self):
        with self.assertRaises(ValueError):supervisor.check_command(command(),None)
        with self.assertRaises(ValueError):supervisor.check_command(command(),pending(),True)

    def test_caller_cannot_supply_pid_or_signal(self):
        for field,value in (('pid',os.getpid()),('signal','SIGTERM')):
            with self.subTest(field=field),self.assertRaises(ValueError):
                supervisor.check_command({**command(),field:value},pending())

    def test_each_binding_component_must_match(self):
        for name,size in supervisor.IDENTIFIERS:
            value=command();value[name]='d'*size
            with self.subTest(name=name),self.assertRaises(ValueError):
                supervisor.check_command(value,pending())

    def test_invalid_binding_encodings_are_rejected(self):
        for bad in ('0'*32,'A'*32,'g'*32,'a'*31,None):
            value=command();value['session_id']=bad
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                supervisor.check_command(value,pending())

    def test_only_kill_action_is_supported(self):
        for action in ('restart','kill -9','',9):
            with self.subTest(action=action),self.assertRaises(ValueError):
                supervisor.check_command({**command(),'action':action},pending())

    def test_authenticated_pending_counters_are_required(self):
        for field,value in (('received_messages',3),('echoed_messages',4),
                            ('pending_payload_bytes',0),('fault_checkpoint',4),('role','client')):
            with self.subTest(field=field),self.assertRaises(ValueError):
                supervisor.check_pending({**pending(),field:value})


@unittest.skipUnless(sys.platform=='linux','Linux process ownership guard')
class OwnedProcessContracts(unittest.TestCase):
    def failed_supervisor(self,data):
        read_fd,write_fd=os.pipe()
        output=io.StringIO()
        try:
            os.write(write_fd,data);os.close(write_fd);write_fd=None
            with os.fdopen(read_fd,'rb',buffering=0) as source:
                with self.assertRaises(ValueError):
                    supervisor.supervise([sys.executable,'-c','import time;time.sleep(5)'],
                                         39401,source,output)
            rows=[json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual([r['event'] for r in rows],['owned_server_started'])
            self.assertIs(rows[0]['parent_death_guard'],True)
            self.assertFalse(Path('/proc',str(rows[0]['child_pid'])).exists(),'owned child was not reaped')
        finally:
            if write_fd is not None:os.close(write_fd)

    def test_controller_eof_kills_and_reaps_only_owned_child(self):
        self.failed_supervisor(b'')

    def test_early_command_is_failed_and_owned_child_is_reaped(self):
        self.failed_supervisor((json.dumps(command())+'\n').encode())

    def test_oversized_command_is_failed_and_owned_child_is_reaped(self):
        self.failed_supervisor(b'x'*(supervisor.COMMAND_LIMIT+1))

    def test_parent_death_kills_disposable_direct_child(self):
        # The test parent does not fork while multithreaded. Its child has a
        # five-second natural bound even if a faulty guard regresses.
        script='''
import subprocess,sys,time
import crash_supervisor as supervisor
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)'],
    preexec_fn=supervisor.parent_death_guard(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(child.pid,flush=True)
time.sleep(5)
'''
        environment=os.environ.copy()
        environment['PYTHONPATH']=str(Path(supervisor.__file__).parent)
        parent=subprocess.Popen([sys.executable,'-B','-c',script],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(parent.stdout,selectors.EVENT_READ)
                self.assertTrue(selector.select(2),'test parent did not create a child')
            line=parent.stdout.readline()
            self.assertTrue(line.strip().isdigit(),line)
            child_pid=int(line)
            parent.kill();self.assertEqual(parent.wait(timeout=2),-9)
            end=time.monotonic()+2
            while time.monotonic()<end:
                try:
                    # An orphan may briefly remain a zombie until init reaps it;
                    # it has already exited and cannot retain sockets or keys.
                    status=Path('/proc',str(child_pid),'stat').read_text().rsplit(')',1)[1].split()[0]
                    if status=='Z':break
                except FileNotFoundError:break
                time.sleep(.01)
            else:self.fail('direct child survived abrupt supervisor death')
        finally:
            if parent.poll() is None:parent.kill()
            parent.wait(timeout=2)
            parent.stdout.close();parent.stderr.close()


if __name__=='__main__':unittest.main()
