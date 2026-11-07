"""Replay reviewed public failure inputs without Atheris; zero inputs is explicit."""
import hashlib
import json
from pathlib import Path
from fuzzing.targets import TARGETS


def main():
    if not __debug__:
        raise RuntimeError('Python -O disables oracles')
    root = Path(__file__).parent/'regressions'
    count = 0
    for name, target in TARGETS.items():
        for path in sorted((root/name).glob('*.bin')):
            if path.stat().st_size > 20000:
                raise ValueError('regression input too large')
            data = path.read_bytes()
            if path.stem != hashlib.sha256(data).hexdigest():
                raise ValueError('regression filename is not its SHA256')
            target(data)
            count += 1
    print(json.dumps({'inputs': count, 'status': 'replayed' if count else 'no_saved_regressions'}))


if __name__ == '__main__':
    main()
