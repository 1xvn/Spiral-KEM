#!/usr/bin/env python3
"""Verify opt2, then measure original, opt1, opt2/SKW1 and ML-KEM-512.

Windows: py compare_spiral_opt2_mlkem.py
Dependency: kyber-py==1.2.0
Fresh sequential exchanges, shuffled order, 30 warm-up + 300 measured each.
The opt2 wire interface uses the explicit lossless compact methods; its KEM
internals continue to hash the unchanged legacy canonical representation.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import sys
import time
import uuid

from compare_spiral_opt1 import stats
from compare_spiral_opt1_mlkem import load_mlkem, measure_mlkem
from verify_opt2 import load_targets, run_checks


ORDER_SEED=20261023
OPERATIONS=('keygen','encapsulate','decapsulate')
LABELS={'original':'Spiral-KEM 0.3.1 baseline', 'opt1':'Spiral-KEM 0.3.1 opt1',
        'opt2':'Spiral-KEM 0.3.1 opt2 (SKW1 lossless 12-bit)',
        'mlkem512':'ML-KEM-512 (kyber-py 1.2.0)'}


def measure_spiral(kem, compact):
    export_pk=kem.serialize_public_key_compact if compact else kem.serialize_public_key
    import_pk=kem.deserialize_public_key_compact if compact else kem.deserialize_public_key
    export_ct=kem.serialize_ciphertext_compact if compact else kem.serialize_ciphertext
    import_ct=kem.deserialize_ciphertext_compact if compact else kem.deserialize_ciphertext
    t0=time.perf_counter_ns()
    pk,sk=kem.keygen()
    t1=time.perf_counter_ns()
    pk_wire=export_pk(pk)
    t2=time.perf_counter_ns()
    received_pk=import_pk(pk_wire)
    t3=time.perf_counter_ns()
    ct,sender_key=kem.encapsulate(received_pk)
    t4=time.perf_counter_ns()
    ct_wire=export_ct(ct)
    t5=time.perf_counter_ns()
    received_ct=import_ct(ct_wire)
    t6=time.perf_counter_ns()
    receiver_key=kem.decapsulate(sk,received_ct)
    t7=time.perf_counter_ns()
    if sender_key!=receiver_key:
        raise ValueError('Key mismatch detected; measurement stopped.')
    expected=(808,1160,32) if compact else (1109,1589,32)
    if (len(pk_wire),len(ct_wire),len(sender_key))!=expected:
        raise ValueError('Unexpected output byte length.')
    row={'keygen_ns':t1-t0,'encapsulate_ns':t4-t3,'decapsulate_ns':t7-t6,
         'pk_export_ns':t2-t1,'pk_import_ns':t3-t2,'ct_export_ns':t5-t4,'ct_import_ns':t6-t5,
         'wire_keygen_ns':t2-t0,'wire_encapsulate_ns':t5-t2,
         'wire_decapsulate_ns':t7-t5,'wire_total_ns':t7-t0}
    row['native_total_ns']=sum(row[op+'_ns'] for op in OPERATIONS)
    return row


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rounds',type=int,default=300)
    parser.add_argument('--warmup',type=int,default=30)
    args=parser.parse_args()
    if not 1<=args.rounds<=10000 or not 0<=args.warmup<=10000:
        parser.error('rounds must be 1..10000 and warmup must be 0..10000.')
    root=Path(__file__).resolve().parent
    modules=load_targets()
    mlkem,package_hashes=load_mlkem()
    environment={'started_utc':datetime.now(timezone.utc).isoformat(),
                 'python':sys.version,'python_implementation':platform.python_implementation(),
                 'platform':platform.platform(),
                 'processor_identifier':platform.processor() or os.environ.get('PROCESSOR_IDENTIFIER','unavailable'),
                 'logical_cpu_count':os.cpu_count(),'cpu_affinity_pinned':False,
                 'garbage_collection_enabled':gc.isenabled(),
                 'warmup_exchanges_each':args.warmup,'measured_exchanges_each':args.rounds,
                 'order_seed':ORDER_SEED,'clock':'time.perf_counter_ns (elapsed wall time)',
                 'schedule':'one process, fresh sequential exchanges, shuffled implementation order each round',
                 'randomness':'normal OS randomness; fixed seeds only in preceding verification fixtures',
                 'source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob('*.py'))},
                 'mlkem_distribution':'kyber-py','mlkem_distribution_version':'1.2.0','mlkem_source_hashes':package_hashes,
                 'timing_scope':{'native':'normal public API calls including internal checks, hashes and legacy canonical encoding',
                                 'wire':'also public-key/ciphertext export and import; opt2 uses SKW1 compact methods, ML-KEM already uses byte APIs',
                                 'network_included':False,'additional_matrix_cache':False},
                 'comparison_scope':'research Python implementations; Spiral noise/compression settings differ from ML-KEM; no equal-security claim'}
    print('Running baseline/opt1/opt2 regressions and lossless wire-format validation first.',flush=True)
    verification=run_checks(modules)
    print('Validation passed. Measuring four implementations in one process.',flush=True)
    targets={name:module.SpiralKEM() for name,module in modules.items()}
    targets['mlkem512']=mlkem
    raw=[]
    order=random.Random(ORDER_SEED)
    print(f'{args.warmup} warmups and {args.rounds} measurements each',flush=True)
    for iteration in range(-args.warmup,args.rounds):
        names=list(targets)
        order.shuffle(names)
        for position,name in enumerate(names):
            row=measure_mlkem(targets[name]) if name=='mlkem512' else measure_spiral(targets[name],name=='opt2')
            if iteration>=0:
                raw.append({'round':iteration+1,'position_in_round':position+1,'implementation':name,**row})
        if iteration>=0 and (iteration+1)%50==0:
            print(f'Measurement progress: {iteration+1}/{args.rounds} (all four implementations)',flush=True)
    metrics=tuple(op+'_ns' for op in OPERATIONS)+('native_total_ns',)+tuple('wire_'+op+'_ns' for op in OPERATIONS)+('wire_total_ns',)
    summaries={}
    for name in targets:
        selected=[r for r in raw if r['implementation']==name]
        pk_bytes,ct_bytes=(808,1160) if name=='opt2' else ((800,768) if name=='mlkem512' else (1109,1589))
        summaries[name]={'label':LABELS[name],'samples':len(selected),'key_mismatches':0,
                         'parameters':({'n':256,'k':2,'q':3329,'eta1':3,'eta2':2,'du':10,'dv':4,'key_bytes':32} if name=='mlkem512' else
                                       {'n':256,'k':2,'q':3329,'eta':1,'key_bytes':32}),
                         'wire_format':('SKW1/v1/lossless12/8-byte-header' if name=='opt2' else
                                        ('ML-KEM-512 byte API' if name=='mlkem512' else 'legacy v0.3 canonical16')),
                         'sizes':{'public_key_bytes':pk_bytes,'ciphertext_bytes':ct_bytes,'shared_key_bytes':32},
                         'timings':{metric:stats([r[metric] for r in selected]) for metric in metrics}}
    medians={name:s['timings']['wire_total_ns']['median_ms'] for name,s in summaries.items()}
    comparison={'opt2_vs_original_wire_total_median_time_reduction_percent':100*(1-medians['opt2']/medians['original']),
                'opt2_vs_opt1_wire_total_median_time_reduction_percent':100*(1-medians['opt2']/medians['opt1']),
                'opt2_over_mlkem_wire_total_median_time_ratio':medians['opt2']/medians['mlkem512'],
                'opt2_public_key_size_reduction_percent':100*(1-808/1109),
                'opt2_ciphertext_size_reduction_percent':100*(1-1160/1589)}
    environment['finished_utc']=datetime.now(timezone.utc).isoformat()
    report={'schema_version':1,'environment':environment,'verification':verification,
            'implementations':summaries,'comparison':comparison,'raw_timings_ns':raw}
    stamp=datetime.now().astimezone().strftime('%Y%m%d_%H%M%S')
    output=root/f'Spiral_opt2_MLKEM_comparison_{stamp}_{uuid.uuid4().hex[:8]}.json'
    with output.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(report,stream,ensure_ascii=False,indent=2,allow_nan=False)
        stream.write('\n')
    print('\nMeasurement complete — median time including byte I/O')
    for name,s in summaries.items():
        print(f'\n{LABELS[name]}')
        for label,metric in (('Key generation','wire_keygen_ns'),('Encapsulation','wire_encapsulate_ns'),('Decapsulation','wire_decapsulate_ns'),('Total','wire_total_ns')):
            print(f"  {label}: {s['timings'][metric]['median_ms']:.3f} ms")
        print(f"  Public key: {s['sizes']['public_key_bytes']} bytes")
        print(f"  Ciphertext: {s['sizes']['ciphertext_bytes']} bytes")
        print(f'  Key mismatches: 0/{args.rounds} (measurement interval)')
    print(f"\nopt2 total time reduction from opt1: {comparison['opt2_vs_opt1_wire_total_median_time_reduction_percent']:.1f}%")
    print(f"opt2 total time / ML-KEM total time: {comparison['opt2_over_mlkem_wire_total_median_time_ratio']:.3f}")
    print('opt2 sizes use the compact wire API; the legacy 16-bit API is also retained.')
    print(f'Results file: {output}')
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError) as error:
        print(f'Error: {error}',file=sys.stderr)
        raise SystemExit(1)
