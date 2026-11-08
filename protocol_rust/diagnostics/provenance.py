"""Identify a checked source bundle or its own Git checkout; never guess a parent."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess


def source_identity(root):
    root=Path(root).resolve()
    manifest=root/'SOURCE.json'
    if manifest.exists():
        raw=manifest.read_bytes()
        data=json.loads(raw)
        commit=data.get('source_commit')
        files=data.get('files')
        if not isinstance(commit,str) or re.fullmatch(r'[0-9a-f]{40}',commit) is None:
            raise ValueError('invalid bundle source commit')
        if not isinstance(files,dict) or not files:
            raise ValueError('bundle manifest must list source files')
        for name,expected in files.items():
            relative=PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or not relative.parts:
                raise ValueError('invalid bundle path: '+name)
            path=root/relative
            if any(part.is_symlink() for part in (path,*path.parents)) or not path.is_file():
                raise ValueError('missing or linked bundle source: '+name)
            if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                raise ValueError('bundle source hash differs: '+name)
        return {'source_identity_kind':'bundle_manifest','source_commit':commit,
          'bundle_manifest_sha256':hashlib.sha256(raw).hexdigest(),'bundle_verified_files':len(files)}
    top=subprocess.check_output(['git','rev-parse','--show-toplevel'],cwd=root,text=True).strip()
    if Path(top).resolve()!=root:
        raise ValueError('Git checkout root differs from source root; SOURCE.json required')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    return {'source_identity_kind':'git','source_commit':commit,'git_commit':commit}
