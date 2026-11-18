"""Verify an isolation receipt offline without extracting or executing its contents."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

from cross_host_smoke import require
from isolation_contract import validate
from load_campaign import strict_json

CASES = ('hold','release','timeout')


def read_archive(path):
    require(path.stat().st_size <= 16*1024*1024, 'compressed archive exceeds limit')
    files = {}
    root = None
    size = 0
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            require(member.isfile() and 2 <= len(parts) <= 3 and '..' not in parts
                    and not member.name.startswith('/') and len(files)<80, 'unexpected archive member')
            if root is None:
                root = parts[0]
            name = '/'.join(parts[1:])
            size += member.size
            require(root == parts[0] and name not in files and member.size <= 12*1024*1024
                    and size <= 32*1024*1024,'duplicate member or excessive size')
            files[name] = archive.extractfile(member).read()
    inventory = strict_json(files.pop('SHA256.json'))
    require(inventory == {k:hashlib.sha256(v).hexdigest() for k,v in files.items()}, 'inventory mismatch')
    return files


def verify(files):
    summary = strict_json(files['summary.json'])
    require(summary['schema']=='spiral-isolation/v1' and summary['status']=='passed'
            and summary['before']==summary['after'], 'invalid run summary')
    before = summary['before']['source']
    require(before['working_tree_dirty'] is False and len(before['git_head'])==40,
            'unidentified run source')
    remote = summary['remote_preparation']
    if summary['scope']=='run':
        require(remote == strict_json(files['public/provenance.json'])
                and remote['source']==before and remote['architecture']=='aarch64'
                and summary['before']['architecture']=='x86_64', 'unexpected cross-host provenance')
    else:
        require(summary['scope']=='local' and remote is None, 'invalid local provenance')
    cases = CASES if summary['requested']=='all' else (summary['requested'],)
    require([r['case'] for r in summary['cases']] == list(cases), 'missing scenario')
    reports = []
    for case, claimed in zip(cases,summary['cases']):
        result = strict_json(files[f'{case}/result.json'])
        require(result == claimed, 'summary disagrees with case result')
        journal = [strict_json(line) for line in files[f'{case}/controller.jsonl'].splitlines()]
        for origin in ('gate','0','1','2','3','4'):
            raw = [strict_json(line) for line in files[f'{case}/{origin}.jsonl'].splitlines()]
            require(raw == [r['data'] for r in journal if r['origin']==origin], 'raw stream mismatch')
        recomputed = validate(case,journal,result['exits'],remote)
        require(json.loads(json.dumps(recomputed))==result, 'replayed result differs')
        reports.append(result)
    return reports


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    reports = verify(read_archive(parser.parse_args().archive))
    print(json.dumps({'status':'passed','cases':[r['case'] for r in reports]}))
