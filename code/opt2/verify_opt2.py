#!/usr/bin/env python3
"""Check legacy compatibility, exact arithmetic and the lossless SKW1 codec."""

from __future__ import annotations

import ast
import contextlib
from dataclasses import replace
import hashlib
import importlib.util
import io
from pathlib import Path
import random
import sys
import unittest
from unittest.mock import patch

from verify_equivalence import load_implementations


def load_targets():
    modules = load_implementations()
    root = Path(__file__).resolve().parent
    if hashlib.sha256((root/'spiral_kem_toy_v031_opt1.py').read_bytes()).hexdigest() != '7ffb12c4494f92327bc560d4579731a642d749ec812e120ad955f6fc49391b51':
        raise ValueError('File differs from the validated opt1 implementation.')
    path = root/'spiral_kem_toy_v031_opt2.py'
    spec = importlib.util.spec_from_file_location('spiral_opt2_verified', path)
    if spec is None or spec.loader is None:
        raise ValueError('Cannot load the opt2 implementation.')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    modules['opt2'] = module
    return modules


def reference12(poly):
    """Independent oracle: one base-4096 integer, little-endian byte order."""
    return sum(value << (12*i) for i,value in enumerate(poly)).to_bytes(len(poly)*3//2, 'little')


def run_checks(modules):
    original, opt1, opt2 = (modules[name] for name in ('original','opt1','opt2'))
    root = Path(__file__).resolve().parent
    counts = {'compact_polynomial_cases': 0, 'noncanonical_12bit_values': 0,
              'deterministic_exchanges': 0, 'tampered_ciphertexts': 0,
              'malformed_compact_wires': 0}

    class Opt2Tests(unittest.TestCase):
        def test_changes_are_limited_and_all_packing_widths_are_four(self):
            changed = {'__init__','_poly_mul','_pack_poly','_unpack_polys'}
            added = {'serialize_public_key_compact','serialize_ciphertext_compact',
                     'deserialize_public_key_compact','deserialize_ciphertext_compact',
                     '_compact_wire_prefix','_pack_compact_poly','_pack_compact_vector',
                     '_unpack_compact_polys'}
            normalized = []
            for filename in ('spiral_kem_toy_v031_opt1.py','spiral_kem_toy_v031_opt2.py'):
                tree = ast.parse((root/filename).read_text(encoding='utf-8'))
                tree.body.pop(0)
                tree.body = [x for x in tree.body if not (
                    isinstance(x, ast.ImportFrom) and x.module == 'struct') and not (
                    isinstance(x, ast.Assign) and any(isinstance(t,ast.Name) and t.id=='COMPACT_WIRE_MAGIC' for t in x.targets))]
                for node in tree.body:
                    if isinstance(node, ast.ClassDef) and node.name=='SpiralKEM':
                        node.body = [x for x in node.body if not (isinstance(x,ast.FunctionDef) and x.name in added)]
                        for method in node.body:
                            if isinstance(method, ast.FunctionDef) and method.name in changed:
                                method.body=[ast.Pass()]
                normalized.append(ast.dump(tree,include_attributes=False))
            self.assertEqual(*normalized)
            for n in original.SUPPORTED_N:
                bound=n*(3329-1)**2
                self.assertEqual((bound.bit_length()+7)//8,4)
                self.assertLess(bound,2**32)

        def test_12bit_codec_against_independent_integer_oracle(self):
            rng=random.Random(20261023)
            for n in original.SUPPORTED_N:
                kem=opt2.SpiralKEM(opt2.Parameters(n=n),lab_mode=n!=256)
                patterns=[(0,)*n,(3328,)*n,tuple(rng.randrange(3329) for _ in range(n))]
                for start in range(0,3329,n):
                    poly=tuple(range(start,min(start+n,3329)))
                    poly=poly+(0,)*(n-len(poly))
                    patterns.extend((poly,poly[::-1]))
                for poly in patterns:
                    expected=reference12(poly)
                    self.assertEqual(kem._pack_compact_poly(poly),expected)
                    self.assertEqual(kem._unpack_compact_polys(expected,1),(poly,))
                    counts['compact_polynomial_cases']+=1
                for position in (0,n-1):
                    for value in (3329,4094,4095):
                        poly=[0]*n
                        poly[position]=value
                        with self.assertRaises(opt2.InputValidationError):
                            kem._unpack_compact_polys(reference12(poly),1)
            kem=opt2.SpiralKEM()
            for value in range(3329,4096):
                for position in (0,1):
                    poly=[0]*256
                    poly[position]=value
                    with self.assertRaises(opt2.InputValidationError):
                        kem._unpack_compact_polys(reference12(poly),1)
                    counts['noncanonical_12bit_values']+=1

        def test_exchange_legacy_bytes_compact_roundtrip_and_fallback(self):
            for n in original.SUPPORTED_N:
                for trial in range(4):
                    fixture=f'public-opt2-fixture/{n}/{trial}'.encode()
                    seeds=[hashlib.sha256(fixture+bytes([i])).digest() for i in range(3)]
                    message=hashlib.shake_256(fixture+b'message').digest(n//8)
                    records=[]
                    for module in (original,opt1,opt2):
                        kem=module.SpiralKEM(module.Parameters(n=n),lab_mode=n!=256)
                        with patch.object(module.secrets,'token_bytes',side_effect=seeds+[message]):
                            pk,sk=kem.keygen()
                            ct,key=kem.encapsulate(pk)
                        records.append((kem,pk,sk,ct,key,kem.serialize_public_key(pk),kem.serialize_ciphertext(ct)))
                        self.assertTrue(kem.decapsulate(sk,ct)==key)
                    for record in records[1:]:
                        self.assertEqual(record[5:],records[0][5:])
                        self.assertTrue(record[2].s==records[0][2].s)
                        self.assertTrue(record[4]==records[0][4])
                    kem,pk,sk,ct,key,pk16,ct16=records[-1]
                    pk12=kem.serialize_public_key_compact(pk)
                    ct12=kem.serialize_ciphertext_compact(ct)
                    self.assertEqual(len(pk12),8+32+2*n*3//2)
                    self.assertEqual(len(ct12),8+3*n*3//2)
                    self.assertEqual(pk12[:8],b'SKW1P'+bytes([original.SUPPORTED_N.index(n)+1])+b'\0\0')
                    self.assertEqual(pk12[40:],b''.join(reference12(poly) for poly in pk.t))
                    self.assertEqual(ct12[8:],b''.join(reference12(poly) for poly in ct.u+(ct.v,)))
                    received_pk=kem.deserialize_public_key_compact(pk12)
                    received_ct=kem.deserialize_ciphertext_compact(ct12)
                    self.assertEqual(received_pk,pk)
                    self.assertEqual(received_ct,ct)
                    self.assertTrue(kem.decapsulate(sk,received_ct)==key)
                    with patch.object(opt2.secrets,'token_bytes',return_value=message):
                        fresh_ct,fresh_key=kem.encapsulate(received_pk)
                    self.assertEqual(fresh_ct,ct)
                    self.assertTrue(fresh_key==key)
                    self.assertEqual(kem.serialize_public_key(kem.deserialize_public_key(pk16)),pk16)
                    self.assertEqual(kem.serialize_ciphertext(kem.deserialize_ciphertext(ct16)),ct16)
                    for field,row in (('v',0),('u',0),('u',1)):
                        for delta in (1,3329//4):
                            fallback_keys=[]
                            for current,current_pk,current_sk,current_ct,current_key,_,_ in records:
                                poly=list(current_ct.v if field=='v' else current_ct.u[row])
                                poly[0]=(poly[0]+delta)%3329
                                if field=='v':
                                    changed=replace(current_ct,v=tuple(poly))
                                else:
                                    u=list(current_ct.u)
                                    u[row]=tuple(poly)
                                    changed=replace(current_ct,u=tuple(u))
                                if current is kem:
                                    changed=kem.deserialize_ciphertext_compact(kem.serialize_ciphertext_compact(changed))
                                fallback=current.decapsulate(current_sk,changed)
                                self.assertTrue(fallback!=current_key)
                                fallback_keys.append(fallback)
                            self.assertTrue(fallback_keys[0]==fallback_keys[1]==fallback_keys[2])
                            counts['tampered_ciphertexts']+=1
                    counts['deterministic_exchanges']+=1

        def test_compact_header_types_lengths_ranges_and_profile_rejection(self):
            for n in original.SUPPORTED_N:
                kem=opt2.SpiralKEM(opt2.Parameters(n=n),lab_mode=n!=256)
                pk,sk=kem.keygen()
                ct,key=kem.encapsulate(pk)
                pk_wire,ct_wire=kem.serialize_public_key_compact(pk),kem.serialize_ciphertext_compact(ct)
                for wire,decode,legacy_decode in ((pk_wire,kem.deserialize_public_key_compact,kem.deserialize_public_key),
                                                 (ct_wire,kem.deserialize_ciphertext_compact,kem.deserialize_ciphertext)):
                    invalid=[None,b'',bytearray(wire),wire[:-1],wire+b'\0']
                    for i in range(8):
                        for bit in range(8):
                            invalid.append(wire[:i]+bytes([wire[i]^(1<<bit)])+wire[i+1:])
                    with patch.object(kem,'_unpack_compact_polys',side_effect=AssertionError('bad header reached coefficient decoding')):
                        for bad in invalid:
                            with self.assertRaises(opt2.InputValidationError):
                                decode(bad)
                            counts['malformed_compact_wires']+=1
                    with self.assertRaises(opt2.InputValidationError):
                        legacy_decode(wire)
                for legacy,decode in ((kem.serialize_public_key(pk),kem.deserialize_public_key_compact),
                                      (kem.serialize_ciphertext(ct),kem.deserialize_ciphertext_compact)):
                    with self.assertRaises(opt2.InputValidationError):
                        decode(legacy)
                bad_coefficient=(3329,)+(0,)*(n-1)
                malformed_pk=pk_wire[:40]+reference12(bad_coefficient)+reference12((0,)*n)
                malformed_ct=ct_wire[:8]+reference12(bad_coefficient)+reference12((0,)*n)*2
                with self.assertRaises(opt2.InputValidationError):
                    kem.deserialize_public_key_compact(malformed_pk)
                with self.assertRaises(opt2.InputValidationError):
                    kem.deserialize_ciphertext_compact(malformed_ct)
                for bad in (None,replace(pk,t=((True,)+pk.t[0][1:],pk.t[1]))):
                    with self.assertRaises(opt2.InputValidationError):
                        kem.serialize_public_key_compact(bad)
                for bad in (None,replace(ct,v=(3329,)+ct.v[1:])):
                    with self.assertRaises(opt2.InputValidationError):
                        kem.serialize_ciphertext_compact(bad)
                if n!=256:
                    baseline=opt2.SpiralKEM()
                    with self.assertRaises(opt2.InputValidationError):
                        baseline.deserialize_public_key_compact(pk_wire)

    logs={}
    log=io.StringIO()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Opt2Tests)
    result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    logs['opt2_differential_and_compact']=log.getvalue()
    if not result.wasSuccessful():
        raise ValueError('opt2 validation failed.\n'+log.getvalue())
    for name,module in modules.items():
        log=io.StringIO()
        with contextlib.redirect_stdout(log):
            passed=module.run_self_test(trials=50)
        logs[name+'_regression']=log.getvalue()
        if not passed:
            raise ValueError(name+' regression tests failed\n'+log.getvalue())
    return {'passed':True,'differential_tests':result.testsRun,'cases':counts,
            'regression_suites_passed':list(modules),'regression_trials':50,'logs':logs}


if __name__=='__main__':
    try:
        import json
        checks=run_checks(load_targets())
        print('Baseline/opt1/opt2 regressions and lossless wire-format validation passed')
        print(json.dumps(checks['cases'],ensure_ascii=False,indent=2))
    except (OSError,ValueError) as error:
        print(str(error),file=sys.stderr)
        raise SystemExit(1)
