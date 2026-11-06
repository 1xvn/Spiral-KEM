"""Exploratory full-call timing diagnostics; never a constant-time certification.

Synthetic secret-key stress fixtures are accepted by the API but are not
KeyGen-consistent. Their timing differences are not a demonstrated attack against
genuine keys or the one-shot protocol. Public validity contrasts are separate.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import replace
from datetime import datetime, timezone
import gc
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import time
from unittest.mock import patch

from protocol_v01.handshake import load_kem


def summary(a, b):
    va, vb = statistics.variance(a), statistics.variance(b)
    ma, mb = statistics.mean(a), statistics.mean(b)
    error2 = va / len(a) + vb / len(b)
    # Infinite statistics are represented by null plus an explicit degeneracy flag.
    t = (ma - mb) / math.sqrt(error2) if error2 else None
    paired = [x - y for x, y in zip(a, b, strict=True)]
    paired_variance = statistics.variance(paired)
    paired_t = statistics.mean(paired) / math.sqrt(paired_variance / len(paired)) if paired_variance else None
    return {'n_per_class': len(a), 'mean_ns': [ma, mb],
            'median_ns': [statistics.median(a), statistics.median(b)],
            'stdev_ns': [math.sqrt(va), math.sqrt(vb)],
            'welch_t': t, 'zero_variance': error2 == 0,
            'paired_t': paired_t,
            'exploratory_abs_t_over_4_5': paired_t is not None and abs(paired_t) > 4.5,
            'paired_mean_difference_ns': statistics.mean(paired),
            'paired_median_difference_ns': statistics.median(paired),
            'min_ns': [min(a), min(b)], 'max_ns': [max(a), max(b)]}


def fixtures():
    module = load_kem()
    kem = module.SpiralKEM()
    # All randomness here is PUBLIC test data, confined to this process/fixture.
    seeds = [hashlib.sha256(b'Spiral timing public fixture/' + bytes([i])).digest() for i in range(4)]
    with patch.object(module.secrets, 'token_bytes', side_effect=seeds):
        pk, sk = kem.keygen()
        ct, correct = kem.encapsulate(pk)
    bad = replace(ct, v=((ct.v[0] + 1) % 3329,) + ct.v[1:])
    assert kem.decapsulate(sk, ct) == correct
    assert kem.decapsulate(sk, bad) != correct
    # z is independently sampled in real KeyGen: changing only z is a genuine
    # supported secret-state contrast while s, pk and public ciphertext stay fixed.
    alternate_z = replace(sk, fallback_secret=hashlib.sha256(b'public timing fixture alternate z').digest())
    assert kem.decapsulate(sk, bad) != kem.decapsulate(alternate_z, bad)
    zeros = (0,) * 256
    one = (1,) + zeros[1:]
    secret_a = replace(sk, s=(zeros, zeros))
    secret_b = replace(sk, s=((3328,) + zeros[1:], zeros))
    chosen = module.Ciphertext((one, zeros), (832,) + zeros[1:])
    assert kem.decapsulate(secret_a, chosen) == kem.decapsulate(secret_b, chosen)
    return {
        'null_same_genuine_key_and_ciphertext': (
            lambda: kem.decapsulate(sk, ct), lambda: kem.decapsulate(sk, ct)),
        'public_valid_vs_canonical_tampered_ciphertext': (
            lambda: kem.decapsulate(sk, ct), lambda: kem.decapsulate(sk, bad)),
        'keygen_consistent_fallback_secret_fixed_public_input': (
            lambda: kem.decapsulate(sk, bad), lambda: kem.decapsulate(alternate_z, bad)),
        'synthetic_secret_fixed_public_input': (
            lambda: kem.decapsulate(secret_a, chosen), lambda: kem.decapsulate(secret_b, chosen)),
    }


def run(pairs=1000, repetitions=3, seed=20261106, output=None, cpu=None):
    if not 100 <= pairs <= 20000 or not 1 <= repetitions <= 10:
        raise ValueError('pairs 100..20000; repetitions 1..10')
    output = Path(output or Path(__file__).parent / 'results' / 'timing.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_path = output.with_suffix('.csv')
    original_affinity = None
    affinity = {'requested_cpu': cpu, 'applied': False}
    try:
        original_affinity = os.sched_getaffinity(0)
        if cpu is None:
            cpu = max(original_affinity)
        os.sched_setaffinity(0, {cpu})
        affinity.update(applied=True, cpu=cpu)
    except (AttributeError, OSError, ValueError) as error:
        affinity['failure_type'] = type(error).__name__
    workloads = fixtures()
    result = {'started_utc': datetime.now(timezone.utc).isoformat(),
              'python': platform.python_version(), 'platform': platform.platform(),
              'clock': 'perf_counter_ns elapsed time around full public decapsulate call',
              'affinity': affinity, 'seed': seed, 'gc_disabled_during_measurement': True,
              'outliers_removed': False, 'pairs_per_repetition': pairs,
              'repetitions': repetitions, 'workloads': {}, 'raw_samples_file': raw_path.name,
              'limits': [
                  'Exploratory paired-t threshold4.5 is not an adjusted significance claim or proof; Welch t is descriptive.',
                  'Pair ordering reduces drift, but samples may still be correlated; no p-values or formal leakage bounds are claimed.',
                  'Synthetic secret stress keys are not KeyGen-consistent; no genuine-key recovery attack is demonstrated.',
                  'Valid vs tampered inputs differ publicly and cannot alone establish secret leakage.',
                  'Same-key repeated local calls exceed the protocol one-shot query model.',
                  'CPU pinning does not remove virtualization, scheduling, frequency, or background-load effects.',
                  'No observed difference is not evidence of constant-time behavior.']}
    started = time.monotonic()
    rng = random.Random(seed)
    gc_was_enabled = gc.isenabled()
    try:
        gc.disable()
        with raw_path.open('w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['workload', 'repetition', 'pair', 'order', 'class', 'elapsed_ns'])
            for name, actions in workloads.items():
                for _ in range(30):
                    actions[0](); actions[1]()
                blocks = []
                for rep in range(repetitions):
                    a, b = [], []
                    for pair in range(pairs):
                        order = [0, 1]
                        rng.shuffle(order)
                        for position, label in enumerate(order):
                            tick = time.perf_counter_ns()
                            value = actions[label]()
                            elapsed = time.perf_counter_ns() - tick
                            if type(value) is not bytes or len(value) != 32:
                                raise RuntimeError('unexpected public API output')
                            (a if label == 0 else b).append(elapsed)
                            writer.writerow([name, rep, pair, position, label, elapsed])
                    blocks.append(summary(a, b))
                flags = [block['exploratory_abs_t_over_4_5'] for block in blocks]
                signs = [math.copysign(1, block['paired_mean_difference_ns']) for block in blocks]
                result['workloads'][name] = {
                    'blocks': blocks, 'flagged_repetitions': sum(flags),
                    'same_direction_in_all_repetitions': len(set(signs)) == 1,
                    'replicated_timing_difference': all(flags) and len(set(signs)) == 1}
                print(name, 'flags', sum(flags), '/', repetitions, flush=True)
        # A detector sanity check with a real deliberately slow action.
        def control(slow):
            if slow:
                end = time.perf_counter_ns() + 50000
                while time.perf_counter_ns() < end:
                    pass
        samples = [[], []]
        for _ in range(1000):
            order = [0, 1]; rng.shuffle(order)
            for label in order:
                tick = time.perf_counter_ns(); control(label)
                samples[label].append(time.perf_counter_ns() - tick)
        result['positive_control'] = summary(*samples)
        result['positive_control']['artificial_delay_ns'] = 50000
        if not result['positive_control']['exploratory_abs_t_over_4_5']:
            raise RuntimeError('timing detector positive control failed')
    finally:
        if gc_was_enabled:
            gc.enable()
        if original_affinity is not None:
            os.sched_setaffinity(0, original_affinity)
    result['elapsed_seconds'] = time.monotonic() - started
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    result['total_decapsulation_samples'] = pairs * 2 * repetitions * len(workloads)
    result['source_sha256'] = {
        str(p.relative_to(Path(__file__).resolve().parents[2])): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [Path(__file__), Path(__file__).resolve().parents[2] / 'code/opt2/spiral_kem_toy_v031_opt2.py']}
    result['status'] = 'measurement_completed_not_a_security_pass'
    output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pairs', type=int, default=1000)
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--seed', type=int, default=20261106)
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--output')
    args = parser.parse_args()
    result = run(args.pairs, args.repetitions, args.seed, args.output, args.cpu)
    print(json.dumps({'status': result['status'], 'samples': result['total_decapsulation_samples'],
                      'elapsed_seconds': result['elapsed_seconds']}))


if __name__ == '__main__':
    main()
