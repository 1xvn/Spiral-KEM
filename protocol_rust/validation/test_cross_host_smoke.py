"""Contract tests only: no SSH, sockets, TLS or external hosts are contacted."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import cross_host_smoke as smoke


def pair():
    session={'session_id':'12'*16,'binding_hash':'34'*32,'transcript_hash':'56'*32,
             'messages':10,'authenticated_close':True}
    server={'status':'passed','role':'server','connections':1,'kem':{'live_keys':0},
            'admission_released':True,'auth_key_closed':True,'sessions':[dict(session)]}
    client={'status':'passed','role':'client','connections':1,'kem':{'live_keys':0},
            'sessions':[dict(session,payload_bytes=1024)]}
    return server,client


def public_bundle(extra=None,link=False):
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w:gz') as tar:
        for name in ['ca.pem','pin.json','provenance.json']+([extra] if extra else []):
            info=tarfile.TarInfo(name)
            value=b'public'
            if link and name=='ca.pem':
                info.type=tarfile.SYMTYPE;info.linkname='/private/key.pem';tar.addfile(info)
            else:
                info.size=len(value);tar.addfile(info,io.BytesIO(value))
    return data.getvalue()


class EndpointContracts(unittest.TestCase):
    def test_accepts_complete_bound_echo_and_close_reports(self):
        self.assertIsNone(smoke.validate_pair(*pair()))

    def test_rejects_mismatch_in_each_binding_field(self):
        for field in ('session_id','binding_hash','transcript_hash'):
            server,client=pair();client['sessions'][0][field]='a'*len(client['sessions'][0][field])
            with self.subTest(field=field),self.assertRaises(ValueError):smoke.validate_pair(server,client)

    def test_rejects_matching_nonhex_or_wrong_size_identifiers(self):
        for field,value in (('session_id','z'*32),('binding_hash','z'*64),('transcript_hash','z'*64),('session_id','12'*32)):
            server,client=pair();server['sessions'][0][field]=value;client['sessions'][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):smoke.validate_pair(server,client)

    def test_rejects_missing_release_or_unclosed_session(self):
        for field in ('admission_released','auth_key_closed'):
            server,client=pair();server[field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):smoke.validate_pair(server,client)
        server,client=pair();client['sessions'][0]['authenticated_close']=False
        with self.assertRaises(ValueError):smoke.validate_pair(server,client)

    def test_rejects_wrong_messages_payload_or_live_keys(self):
        for change in ('messages','payload','live'):
            server,client=pair()
            if change=='messages':client['sessions'][0]['messages']=9
            if change=='payload':client['sessions'][0]['payload_bytes']=64
            if change=='live':client['kem']['live_keys']=1
            with self.subTest(change=change),self.assertRaises(ValueError):smoke.validate_pair(server,client)


class PublicBundleContracts(unittest.TestCase):
    def test_accepts_only_three_named_public_files(self):
        self.assertEqual(set(smoke.public_files(public_bundle())),{'ca.pem','pin.json','provenance.json'})

    def test_rejects_private_or_traversal_members(self):
        for name in ('auth.bin','key.pem','../key.pem'):
            with self.subTest(name=name),self.assertRaises(ValueError):smoke.public_files(public_bundle(name))

    def test_rejects_symlink_members(self):
        with self.assertRaises(ValueError):smoke.public_files(public_bundle(link=True))


class ListenerAndOutputContracts(unittest.TestCase):
    def test_listener_requires_ssh_process_socket_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'net').mkdir();(root/'42/fd').mkdir(parents=True)
            port=39401
            (root/'net/tcp').write_text('header\n0: 0100007F:%04X 00000000:0000 0A 0 0 0 0 0 123\n'%port)
            (root/'42/fd/3').symlink_to('socket:[999]')
            self.assertTrue(smoke.listening(port,proc=root))
            self.assertFalse(smoke.listening(port,42,root))
            (root/'42/fd/3').unlink();(root/'42/fd/3').symlink_to('socket:[123]')
            self.assertTrue(smoke.listening(port,42,root))

    def test_final_report_uses_final_json_and_rejects_empty_output(self):
        report={'status':'passed'}
        self.assertEqual(smoke.final_report(b'{"listening":39401}\n'+json.dumps(report).encode()+b'\n'),report)
        with self.assertRaises(ValueError):smoke.final_report(b'')

    def test_wrong_pin_keeps_metadata_and_changes_only_public_key(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);pin={'public_key_hex':'12'*32,'not_before':1,'not_after':999,'revoked':False,'server_name':smoke.NAME,'service':smoke.SERVICE}
            (root/'pin.json').write_text(json.dumps(pin))
            args=smoke.client_command(39401,root,True)
            wrong=json.loads((root/'wrong-pin.json').read_text())
            self.assertEqual(wrong,dict(pin,public_key_hex='00'*32))
            self.assertEqual(json.loads((root/'pin.json').read_text()),pin)
            self.assertNotIn('--auth',args);self.assertNotIn('--key',args)


if __name__=='__main__':unittest.main()
