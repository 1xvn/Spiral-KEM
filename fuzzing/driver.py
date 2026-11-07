"""Atheris child process. Only declared runtime code receives instrumentation."""
import argparse
import hashlib
import inspect
import json
from pathlib import Path
import sys

import atheris
from fuzzing import targets
from protocol_v01 import wire, handshake, records

ROOT = Path(__file__).resolve().parents[1]
MODULES = {'frame': [wire], 'hello': [handshake],
           'kem_pk': [targets.KEM_MODULE], 'kem_ct': [targets.KEM_MODULE],
           'records': [wire, records]}


def instrument(modules):
    seen = set()
    names = []
    def function(value, name, module):
        if not inspect.isfunction(value) or id(value) in seen:
            return
        if value.__module__ != module.__name__:
            return
        if Path(value.__code__.co_filename).resolve() != Path(module.__file__).resolve():
            return
        seen.add(id(value))
        old = value.__code__.co_code
        # Atheris3.1 mutates this same function object, so existing imported
        # aliases in records/handshake receive instrumentation too.
        atheris.instrument_func(value)
        if old == value.__code__.co_code:
            raise RuntimeError('runtime function was not instrumented: ' + name)
        names.append(name)
    for module in modules:
        for name, value in vars(module).items():
            function(value, module.__name__ + '.' + name, module)
            if inspect.isclass(value) and value.__module__ == module.__name__:
                for method, member in vars(value).items():
                    if isinstance(member, (staticmethod, classmethod)):
                        member = member.__func__
                    if isinstance(member, property):
                        for suffix, func in [('get', member.fget), ('set', member.fset), ('del', member.fdel)]:
                            function(func, module.__name__ + '.' + name + '.' + method + '.' + suffix, module)
                    else:
                        function(member, module.__name__ + '.' + name + '.' + method, module)
    if not names:
        raise RuntimeError('no runtime instrumentation')
    return names


def main():
    if not __debug__:
        raise RuntimeError('fuzz oracles require assertions; Python -O is forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=sorted(targets.TARGETS), required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    args, engine_args = parser.parse_known_args()
    names = instrument(MODULES[args.target])
    metadata = {'target': args.target, 'instrumented_runtime_functions': names,
                'instrumentation_count': len(names),
                'instrumentation': 'Atheris3.1 Python bytecode basic blocks/comparisons; named nested functions/lambdas included, generator/comprehension code may be skipped; runtime only',
                'harness_oracle_instrumented': False,
                'source_sha256': {str(Path(m.__file__).resolve().relative_to(ROOT)):
                    hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in MODULES[args.target]}}
    args.metadata.write_text(json.dumps(metadata, indent=2) + '\n')
    # This callback and independent oracles are intentionally not decorated.
    # Feedback must come from actual runtime functions, not harness routing.
    atheris.Setup([sys.argv[0], *engine_args], targets.TARGETS[args.target])
    atheris.Fuzz()


if __name__ == '__main__':
    main()
