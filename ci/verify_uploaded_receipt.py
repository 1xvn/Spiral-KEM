"""Fetch the upload action's immutable artifact ID and verify its only ZIP member."""
import argparse
import io
from pathlib import Path
import subprocess
import time
import zipfile


def verify(raw, receipt):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if archive.namelist() != ['receipt.json'] or archive.read('receipt.json') != receipt:
            raise ValueError('uploaded file set or receipt bytes differ')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact_id', type=int)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    receipt = args.receipt.read_bytes()
    for attempt in range(5):
        result = subprocess.run(['gh', 'api', 'repos/{owner}/{repo}/actions/artifacts/' +
                                 str(args.artifact_id) + '/zip'], capture_output=True, timeout=45)
        if result.returncode == 0:
            verify(result.stdout, receipt)
            print(f'Verified receipt.json in artifact {args.artifact_id}')
            return
        if attempt < 4:
            time.sleep(2 ** attempt)
    raise SystemExit('GitHub could not return the uploaded archive by ID')


if __name__ == '__main__':
    main()
