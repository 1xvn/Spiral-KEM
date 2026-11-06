"""Bounded, deterministic mutation/property campaign, not coverage-guided fuzzing.

Run at repository root: python -m protocol_v01.validation.fuzz_campaign.
Only public synthetic fixture keys/inputs are used. Unexpected exceptions and
oracle mismatches fail the process and preserve the seed, index and public input.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import platform
import random
import re
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

import cryptography

from protocol_v01.handshake import load_kem, parse_client_hello
from protocol_v01.records import RecordState
from protocol_v01.wire import ProtocolError, parse_frame

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'protocol_v01/tests/fixtures/test_vectors_v0.1.json'
DEFAULT_OUTPUT = Path(__file__).resolve().parent / 'results/fuzz.json'
SEED = 2026110603


def change(raw, offset, rng):
    return raw[:offset] + bytes([raw[offset] ^ rng.randrange(1, 256)]) + raw[offset+1:]


def replace_coefficient(raw, offset, index, value):
    payload = int.from_bytes(raw[offset:], 'little')
    mask = 4095 << (12*index)
    return raw[:offset] + ((payload & ~mask) | (value << (12*index))).to_bytes(len(raw)-offset, 'little')


def kem_oracle(raw, kind):
    offset, count = (40, 512) if kind == 'pk' else (8, 768)
    prefix = b'SKW1' + (b'P' if kind == 'pk' else b'C') + b'\x06\0\0'
    if type(raw) is not bytes or len(raw) != offset + count*3//2 or raw[:8] != prefix:
        return False
    value = int.from_bytes(raw[offset:], 'little')
    return all(((value >> (12*i)) & 4095) < 3329 for i in range(count))


def frame_oracle(raw, expected):
    if type(raw) is not bytes or len(raw)<40 or raw[:6] != b'SPK1\0\1':
        return False
    kind, role = raw[6], raw[7]
    suite, flags = int.from_bytes(raw[8:10],'big'), int.from_bytes(raw[10:12],'big')
    sid, seq, length = raw[12:28], int.from_bytes(raw[28:36],'big'), int.from_bytes(raw[36:40],'big')
    sizes={1:(75,418),2:(940,940),3:(1192,1192),4:(32,32),16:(17,16400),17:(17,17)}
    if kind not in sizes or role not in (0,1) or flags or suite!=(0 if kind==1 else 0xf001):
        return False
    if not sizes[kind][0]<=length<=sizes[kind][1] or length!=len(raw)-40:
        return False
    if kind<5:
        if (role,seq)!={1:(0,0),2:(1,0),3:(0,1),4:(1,1)}[kind]: return False
    elif seq>=2**20 or (kind==16 and seq==2**20-1): return False
    if (kind==1)!=(sid==bytes(16)): return False
    return all(actual == expected[name] for name,actual in [('kind',kind),('role',role),('sid',sid),('sequence',seq)])


def ch_oracle(raw):
    if type(raw) is not bytes or not 75<=len(raw)<=418: return False
    at=64
    def read(n):
        nonlocal at
        if at+n>len(raw): raise ValueError('short')
        value=raw[at:at+n]; at+=n
        return value
    try:
        offers=[]
        for _ in range(2):
            n=read(1)[0]
            if not 1<=n<=8: return False
            values=[int.from_bytes(read(2),'big') for _ in range(n)]
            if not values[0] or values!=sorted(set(values)): return False
            offers.append(values)
        if 1 not in offers[0] or 0xf001 not in offers[1]: return False
        n=int.from_bytes(read(2),'big')
        if not 1<=n<=253: return False
        host=read(n).decode('ascii')
        n=read(1)[0]
        if not 1<=n<=64: return False
        service=read(n).decode('ascii')
        if at!=len(raw): return False
        for label in host.split('.'):
            if not 1<=len(label)<=63 or not re.fullmatch('[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?',label): return False
        try: ipaddress.ip_address(host)
        except ValueError: pass
        else: return False
        return re.fullmatch('[a-z0-9][a-z0-9._/-]{0,63}',service) is not None
    except (ValueError,UnicodeError,IndexError): return False


class Campaign:
    def __init__(self, seed, cases):
        self.rng=random.Random(seed)
        self.seed=seed
        self.cases=cases
        self.stats={}
        self.current={}
        self.report={
            'campaign':'Spiral OPT2 item3 bounded mutation/property fuzz',
            'seed':seed, 'cases_per_main_target':cases,
            'started_utc':datetime.now(timezone.utc).isoformat(),
            'method':'Deterministic structure-aware mutation/property testing with independent acceptance/canonicality oracles; not coverage-guided fuzzing.',
            'python':platform.python_version(), 'cryptography':cryptography.__version__, 'targets':self.stats,
            'limits':['Finite fixed-seed sample; no exhaustive input-space coverage or security proof.',
                      'No timing/cache leakage or remote service load measurement in this campaign.',
                      'No branch/line coverage claimed; acceptance/rejection counts are not coverage metrics.'],
        }

    def case(self, target, category, index, raw, expected, operation, error_type, accepted=None, rejected=None):
        stat=self.stats.setdefault(target,{'cases':0,'accepted':0,'rejected':0,'errors':0,'categories':{}})
        stat['cases']+=1
        stat['categories'][category]=stat['categories'].get(category,0)+1
        self.current={'target':target,'category':category,'index':index,'expected_accept':expected}
        if type(raw) is bytes:
            self.current.update(input_length=len(raw),input_sha256=hashlib.sha256(raw).hexdigest())
            if len(raw)<=20000: self.current['public_input_hex']=raw.hex()
            else: self.current['public_prefix_hex']=raw[:128].hex()
        else: self.current['input_type']=type(raw).__name__
        try:
            value=operation()
        except error_type:
            stat['rejected']+=1
            if expected: raise AssertionError('reference-valid input rejected')
            if rejected: rejected()
        except BaseException:
            stat['errors']+=1
            raise
        else:
            stat['accepted']+=1
            if not expected: raise AssertionError('reference-invalid input accepted')
            if accepted: accepted(value)

    def run(self):
        rng=self.rng
        fixture=json.loads(FIXTURE.read_text())
        module=load_kem(); kem=module.SpiralKEM()
        frames={k:bytes.fromhex(v) for k,v in fixture['frames'].items()}
        for kind in ('pk','ct'):
            raw0=bytes.fromhex(fixture['public']['kem_public_key_skw1' if kind=='pk' else 'kem_ciphertext_skw1'])
            offset,count=(40,512) if kind=='pk' else (8,768)
            decode=kem.deserialize_public_key_compact if kind=='pk' else kem.deserialize_ciphertext_compact
            encode=kem.serialize_public_key_compact if kind=='pk' else kem.serialize_ciphertext_compact
            for i in range(self.cases):
                mode=i%8
                if mode==0:
                    poly=[rng.randrange(3329) for _ in range(count)]
                    blob=sum(value<<(12*j) for j,value in enumerate(poly)).to_bytes(count*3//2,'little')
                    raw=raw0[:offset]+blob; cat='generated_canonical_polynomials'
                elif mode==1:
                    raw=change(raw0,rng.randrange(offset,len(raw0)),rng);cat='payload_byte_flip'
                elif mode==2:
                    raw=replace_coefficient(raw0,offset,rng.randrange(count),rng.randrange(3329,4096));cat='noncanonical_coefficient'
                elif mode==3:
                    raw=change(raw0,rng.randrange(8),rng);cat='header_byte_flip'
                elif mode==4:
                    raw=raw0[:rng.randrange(len(raw0))];cat='truncation'
                elif mode==5:
                    raw=raw0+rng.randbytes(rng.randrange(1,32));cat='extension'
                elif mode==6:
                    raw=[None,bytearray(raw0),memoryview(raw0),'bad'][rng.randrange(4)];cat='wrong_type'
                else:
                    raw=replace_coefficient(raw0,offset,rng.randrange(count),rng.choice([0,1,3328]));cat='canonical_edge_coefficient'
                def canonical(value,raw=raw):
                    assert encode(value)==raw, 'accepted KEM wire not byte-canonical'
                self.case('kem_'+kind,cat,i,raw,kem_oracle(raw,kind),lambda:decode(raw),module.InputValidationError,canonical)

        names=list(frames)
        for i in range(self.cases):
            base=frames[rng.choice(names)]
            expected={'kind':base[6],'role':base[7],'sid':base[12:28],'sequence':int.from_bytes(base[28:36],'big')}
            mode=i%8
            if mode==0: raw=change(base,rng.randrange(40,len(base)),rng);cat='uninterpreted_payload_mutation'
            elif mode==1: raw=change(base,rng.randrange(40),rng);cat='header_mutation'
            elif mode==2: raw=base[:rng.randrange(len(base))];cat='truncation'
            elif mode==3: raw=base+rng.randbytes(rng.randrange(1,16));cat='extension'
            elif mode==4:
                raw=base[:28]+rng.choice([2**20-1,2**20,2**64-1]).to_bytes(8,'big')+base[36:];cat='sequence_boundary'
            elif mode==5:
                raw=base[:36]+rng.choice([0,16,17,16384,16400,16401,2**32-1]).to_bytes(4,'big')+base[40:];cat='declared_length_boundary'
            elif mode==6: raw=rng.choice([None,bytearray(base),'bad']);cat='wrong_type'
            else: raw=base;cat='valid_fixture'
            def exact(frame,raw=raw):
                assert frame.header.raw+frame.payload==raw
            self.case('frame',cat,i,raw,frame_oracle(raw,expected),lambda:parse_frame(raw,**expected),ProtocolError,exact)

        ch0=frames['client_hello'][40:]
        for i in range(self.cases):
            mode=i%8
            if mode==0:
                raw=rng.randbytes(64)+ch0[64:];cat='random_and_exporter_fields'
            elif mode==1:
                versions=[1]+sorted(rng.sample(range(2,500),rng.randrange(8)))
                suites=sorted([0xf001]+rng.sample(range(2,1000),rng.randrange(8)))
                raw=ch0[:64]+bytes([len(versions)])+b''.join(x.to_bytes(2,'big') for x in versions)+bytes([len(suites)])+b''.join(x.to_bytes(2,'big') for x in suites)+ch0[70:]
                cat='valid_sorted_offer_lists'
            elif mode==2: raw=change(ch0,rng.randrange(64,len(ch0)),rng);cat='schema_field_mutation'
            elif mode==3: raw=ch0[:64]+rng.choice([b'\0',b'\x09',b'\xff'])+ch0[65:];cat='offer_count_boundary'
            elif mode==4: raw=ch0[:rng.randrange(len(ch0))];cat='truncation'
            elif mode==5: raw=ch0+rng.randbytes(rng.randrange(1,16));cat='extension'
            elif mode==6: raw=rng.choice([None,bytearray(ch0),'bad']);cat='wrong_type'
            else:
                host=rng.choice([b'a.example',b'A.example',b'a..example',b'-a.example',b'127.0.0.1',b'a'*64+b'.example',b'a.example.'])
                service=rng.choice([b'spiral-research',b'test/valid',b'UPPER',b'',b'a'*65])
                raw=ch0[:70]+len(host).to_bytes(2,'big')+host+bytes([len(service)])+service;cat='identity_grammar_boundary'
            self.case('client_hello',cat,i,raw,ch_oracle(raw),lambda:parse_client_hello(raw),ProtocolError)

        keys=SimpleNamespace(sid=bytes.fromhex(fixture['public']['session_id']),
              c_key=bytes.fromhex(fixture['expected']['client_data_key']),
              s_key=bytes.fromhex(fixture['expected']['server_data_key']),
              c_prefix=bytes.fromhex(fixture['expected']['client_nonce_prefix']),
              s_prefix=bytes.fromhex(fixture['expected']['server_nonce_prefix']))
        for i in range(self.cases):
            role=rng.randrange(2);sender=RecordState(keys,role,clock=lambda:0); receiver=RecordState(keys,1-role,clock=lambda:0)
            plaintext=rng.randbytes(rng.randrange(1,257))
            valid=sender.encode_data(plaintext)
            mode=i%8
            if mode==0: raw=valid;cat='valid_authenticated_record';expected=True
            elif mode==1:
                assert receiver.decode(valid)==(16,plaintext)
                raw=valid;cat='replayed_authenticated_record';expected=False
            elif mode==2: raw=change(valid,rng.randrange(40,len(valid)),rng);cat='ciphertext_or_tag_flip';expected=False
            elif mode==3: raw=change(valid,rng.randrange(40),rng);cat='aad_header_flip';expected=False
            elif mode==4: raw=valid[:28]+(1).to_bytes(8,'big')+valid[36:];cat='skipped_sequence';expected=False
            elif mode==5: raw=valid[:rng.randrange(len(valid))];cat='truncation';expected=False
            elif mode==6: raw=valid+valid;cat='coalesced_frames_given_to_single_frame_api';expected=False
            else: raw=bytearray(valid);cat='wrong_type';expected=False
            def delivered(value):
                assert value==(16,plaintext), 'wrong authenticated plaintext delivered'
                assert receiver.receive_sequence==1
            def permanent():
                assert receiver.failed, 'rejection did not permanently invalidate session'
                assert receiver._receive_key is None and receiver._send_key is None
                try: receiver.decode(valid)
                except ProtocolError: pass
                else: raise AssertionError('session revived after failure')
            self.case('record',cat,i,raw,expected,lambda:receiver.decode(raw),ProtocolError,delivered,permanent)

        # Few explicitly bounded large inputs, not repeated for every mutation.
        for size in (16401,65536,8*1024*1024):
            raw=b'\0'*size
            for target,op,err in [('oversize_pk',lambda:kem.deserialize_public_key_compact(raw),module.InputValidationError),
                                  ('oversize_ct',lambda:kem.deserialize_ciphertext_compact(raw),module.InputValidationError),
                                  ('oversize_frame',lambda:parse_frame(raw),ProtocolError),
                                  ('oversize_ch',lambda:parse_client_hello(raw),ProtocolError)]:
                self.case(target,'bounded_large_input',size,raw,False,op,err)

        seeds=fixture['inputs']['kem_test_seeds']
        with patch.object(module.secrets,'token_bytes',side_effect=[bytes.fromhex(seeds[k]) for k in ('matrix','secret','fallback')]):
            pk,sk=kem.keygen()
        ct0=bytes.fromhex(fixture['public']['kem_ciphertext_skw1'])
        legitimate=kem.decapsulate(sk,kem.deserialize_ciphertext_compact(ct0))
        for i in range(256):
            # Change one canonical coefficient and retain proper SKW1 format.
            j=rng.randrange(768)
            old=(int.from_bytes(ct0[8:],'little')>>(12*j))&4095
            raw=replace_coefficient(ct0,8,j,(old+rng.randrange(1,3329))%3329)
            ct=kem.deserialize_ciphertext_compact(raw)
            def fallback(value):
                assert len(value)==32 and value!=legitimate
                assert kem.decapsulate(sk,ct)==value, 'fallback not deterministic'
            self.case('kem_fallback','canonical_tampered_ciphertext',i,raw,True,lambda:kem.decapsulate(sk,ct),module.InputValidationError,fallback)
        self.report['fallback_decapsulation_calls']=513  # baseline1 + 256*2
        self.report['status']='passed'
        return self.report


def main():
    if not __debug__:
        raise RuntimeError('Run without Python -O: fuzz oracle assertions must remain enabled')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=int,default=SEED)
    parser.add_argument('--cases-per-target',type=int,default=20000)
    parser.add_argument('--output',type=Path,default=DEFAULT_OUTPUT)
    args=parser.parse_args()
    if not 1<=args.cases_per_target<=200000: parser.error('cases per target must be 1..200000')
    campaign=Campaign(args.seed,args.cases_per_target)
    started=time.monotonic()
    try:
        result=campaign.run()
        code=0
    except BaseException as exc:
        result=campaign.report
        result.update(status='failed',failure={**campaign.current,'exception':type(exc).__name__,'message':str(exc)})
        code=1
    result['finished_utc']=datetime.now(timezone.utc).isoformat()
    result['elapsed_seconds']=time.monotonic()-started
    result['total_cases']=sum(v['cases'] for v in result['targets'].values())
    result['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [
        Path(__file__),ROOT/'protocol_v01/wire.py',ROOT/'protocol_v01/handshake.py',
        ROOT/'protocol_v01/records.py',ROOT/'code/opt2/spiral_kem_toy_v031_opt2.py',FIXTURE]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'cases':result['total_cases'],'seconds':result['elapsed_seconds'],'output':str(args.output)},indent=2))
    if code: print(json.dumps(result['failure'],indent=2),file=sys.stderr)
    raise SystemExit(code)


if __name__=='__main__': main()
