#!/usr/bin/env python3
"""Check sampler equivalence, wire compatibility, and both regression suites."""

from __future__ import annotations

import ast
import contextlib
from dataclasses import replace
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ORIGINAL_SHA256 = "898e540b4aded14e3710b591c6aa03a44bf5774c1d591f630e488b041655fd6c"
SOURCE_NAMES = {"original": "spiral_kem_toy_v031.py", "opt1": "spiral_kem_toy_v031_opt1.py"}


def load_implementations():
    root = Path(__file__).resolve().parent
    modules = {}
    for label, filename in SOURCE_NAMES.items():
        path = root / filename
        if label == "original" and hashlib.sha256(path.read_bytes()).hexdigest() != ORIGINAL_SHA256:
            raise ValueError("Baseline 0.3.1 file SHA-256 mismatch.")
        name = "spiral_opt1_comparison_" + label
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ValueError("Cannot read the implementation file.")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        modules[label] = module
    return modules


def run_checks(modules):
    original, optimized = modules["original"], modules["opt1"]
    root = Path(__file__).resolve().parent
    counts = {"exhaustive_byte_pairs": 0, "seed_label_profile_cases": 0,
              "end_to_end_cases": 0, "tampered_ciphertext_cases": 0}

    class EquivalenceTests(unittest.TestCase):
        def test_only_sampler_code_changed(self):
            trees = []
            for filename in SOURCE_NAMES.values():
                tree = ast.parse((root / filename).read_text(encoding="utf-8"))
                if isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
                    tree.body.pop(0)  # Ignore the explanatory module docstring.
                for node in tree.body:
                    if isinstance(node, ast.ClassDef) and node.name == "SpiralKEM":
                        for method in node.body:
                            if isinstance(method, ast.FunctionDef) and method.name == "_small_poly":
                                method.body = [ast.Pass()]
                trees.append(ast.dump(tree, include_attributes=False))
            self.assertEqual(*trees)

        def test_all_65536_byte_pairs_and_xof_calls(self):
            a, b = original.SpiralKEM(), optimized.SpiralKEM()
            stream = bytes(value for positive in range(256) for negative in range(256)
                           for value in (positive, negative))
            for start in range(0, len(stream), 512):
                block = stream[start:start + 512]
                outputs = []
                for kem in (a, b):
                    with patch.object(kem, "_xof", return_value=block) as xof:
                        outputs.append(kem._small_poly(b"test-seed", b"all-pairs"))
                    xof.assert_called_once_with(b"small/all-pairs", b"test-seed", 512)
                self.assertEqual(*outputs)
                counts["exhaustive_byte_pairs"] += len(block) // 2

        def test_seed_label_combinations_all_supported_profiles(self):
            labels = tuple(prefix + b"/" + i.to_bytes(2, "little")
                           for prefix in (b"key/s", b"key/e", b"enc/r", b"enc/e1")
                           for i in range(2)) + (b"enc/e2",)
            for n in original.SUPPORTED_N:
                a = original.SpiralKEM(original.Parameters(n=n), lab_mode=n != 256)
                b = optimized.SpiralKEM(optimized.Parameters(n=n), lab_mode=n != 256)
                for trial in range(16):
                    seed = hashlib.sha256(f"public-test-seed/{n}/{trial}".encode()).digest()
                    for label in labels:
                        self.assertEqual(a._small_poly(seed, label), b._small_poly(seed, label))
                        counts["seed_label_profile_cases"] += 1

        def test_full_exchange_wire_compatibility_and_fallback(self):
            for n in original.SUPPORTED_N:
                for trial in range(4):
                    seed = f"public-fixture/{n}/{trial}".encode()
                    fixtures = [hashlib.sha256(seed + bytes([i])).digest() for i in range(3)]
                    fixtures.append(hashlib.shake_256(seed + b"message").digest(n // 8))
                    records = []
                    for module in (original, optimized):
                        kem = module.SpiralKEM(module.Parameters(n=n), lab_mode=n != 256)
                        # Fixed randomness is confined to public test fixtures.
                        with patch.object(module.secrets, "token_bytes", side_effect=fixtures) as rng:
                            pk, sk = kem.keygen()
                            ct, key = kem.encapsulate(pk)
                        self.assertEqual([c.args[0] for c in rng.call_args_list], [32, 32, 32, n // 8])
                        self.assertTrue(kem.decapsulate(sk, ct) == key)
                        records.append((kem, sk, ct, key, kem.serialize_public_key(pk), kem.serialize_ciphertext(ct)))
                    self.assertTrue(records[0][1].s == records[1][1].s)
                    self.assertTrue(records[0][3] == records[1][3])
                    self.assertEqual(records[0][4:], records[1][4:])
                    for index, (kem, sk, ct, key, pk_wire, ct_wire) in enumerate(records):
                        other = records[1 - index]
                        self.assertEqual(kem.serialize_public_key(kem.deserialize_public_key(other[4])), pk_wire)
                        self.assertTrue(kem.decapsulate(sk, kem.deserialize_ciphertext(other[5])) == key)
                    for field, row in (("v", 0), ("u", 0), ("u", 1)):
                        for delta in (1, 3329 // 4):
                            fallback_keys = []
                            for kem, sk, ct, key, pk_wire, ct_wire in records:
                                poly = list(ct.v if field == "v" else ct.u[row])
                                poly[0] = (poly[0] + delta) % kem.p.q
                                if field == "v":
                                    changed = replace(ct, v=tuple(poly))
                                else:
                                    u = list(ct.u)
                                    u[row] = tuple(poly)
                                    changed = replace(ct, u=tuple(u))
                                fallback = kem.decapsulate(sk, changed)
                                self.assertTrue(fallback != key)
                                fallback_keys.append(fallback)
                            self.assertTrue(fallback_keys[0] == fallback_keys[1])
                            counts["tampered_ciphertext_cases"] += 1
                    counts["end_to_end_cases"] += 1

    logs = {}
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(EquivalenceTests))
    logs["equivalence"] = log.getvalue()
    if not result.wasSuccessful():
        raise ValueError("Equivalence validation failed.\n" + log.getvalue())
    for label, module in modules.items():
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            passed = module.run_self_test(trials=50)
        logs[label + "_regression"] = log.getvalue()
        if not passed:
            raise ValueError(label + " regression tests failed.\n" + log.getvalue())
    return {"passed": True, "equivalence_tests": result.testsRun,
            "regression_suites": {"original": {"passed": True, "trials": 50},
                                  "opt1": {"passed": True, "trials": 50}},
            "cases": counts, "logs": logs}


if __name__ == "__main__":
    try:
        import json
        checks = run_checks(load_implementations())
        print("Baseline/optimized regressions and equivalence validation passed.")
        print(json.dumps(checks["cases"], ensure_ascii=False, indent=2))
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
