"""Replay one saved public input without needing Atheris."""
import argparse
from pathlib import Path
from fuzzing.targets import TARGETS


def main():
    if not __debug__:
        raise RuntimeError('Python -O disables fuzz oracles')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', choices=sorted(TARGETS), required=True)
    p.add_argument('input', type=Path)
    args = p.parse_args()
    data = args.input.read_bytes()
    if len(data) > 20000:
        p.error('replay inputs are limited to 20000 bytes')
    TARGETS[args.target](data)
    print('Replay completed without oracle failure. A documented rejection is a normal result.')


if __name__ == '__main__':
    main()
