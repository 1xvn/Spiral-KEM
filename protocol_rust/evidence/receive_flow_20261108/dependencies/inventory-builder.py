"""Read cached locked crates; retain small provenance-checked source excerpts."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib

root=Path('/workspace/Spiral-KEM')
cache=Path('/workspace/rust48-tools/cargo-cache/registry')
index='index.crates.io-1949cf8c6b5b557f'
out=Path('/workspace/receive-dependency-inventory-20261108')
out.mkdir(exist_ok=False)
selections={
 'hmac':{'src/optim.rs':[(17,37),(49,59),(202,220)]},
 'hkdf':{'src/lib.rs':[(163,173),(189,197),(234,262)]},
 'sha2':{'src/core_api.rs':[(17,24),(89,96)]},
 'digest':{'src/core_api/wrapper.rs':[(22,33),(162,174)]},
 'chacha20poly1305':{'src/cipher.rs':[(27,44),(82,96)],'src/lib.rs':[(291,301)]},
 'chacha20':{'src/lib.rs':[(307,317)]},
 'poly1305':{'src/backend/autodetect.rs':[(97,105)],'src/backend/soft.rs':[(235,243)]},
 'ed25519-dalek':{'src/signing.rs':[(658,666),(809,815)],'src/hazmat.rs':[(66,76)]},
 'zeroize':{'src/lib.rs':[(760,772)]},
}
lock=tomllib.loads((root/'protocol_rust/Cargo.lock').read_text())
env=dict(os.environ,CARGO_HOME='/workspace/rust48-tools/cargo-cache',CARGO_NET_OFFLINE='true',
 RUSTC='/workspace/rust48-tools/rust/bin/rustc',RUSTDOC='/workspace/rust48-tools/rust/bin/rustdoc')
metadata=json.loads(subprocess.check_output(['/workspace/rust48-tools/rust/bin/cargo','metadata','--locked','--offline','--filter-platform','x86_64-unknown-linux-gnu','--format-version=1','--manifest-path',str(root/'protocol_rust/Cargo.toml')],env=env))
nodes={r['id']:r for r in metadata['resolve']['nodes']}
packages={r['name']:r for r in metadata['packages'] if r['name'] in selections}
report={'scope':'Pinned dependency source inventory, not a complete stack/register wipe proof or vulnerability verdict.',
 'cargo_lock_sha256':hashlib.sha256((root/'protocol_rust/Cargo.lock').read_bytes()).hexdigest(),'packages':[]}
excerpt=[]
for name,files in selections.items():
    matches=[r for r in lock['package'] if r['name']==name]
    assert len(matches)==1
    package=matches[0];prefix=f"{name}-{package['version']}"
    archive=cache/'cache'/index/(prefix+'.crate')
    archivehash=hashlib.sha256(archive.read_bytes()).hexdigest()
    assert archivehash==package['checksum']
    row={'name':name,'version':package['version'],'crate_sha256':archivehash,'matches_lock':True,
      'features':nodes[packages[name]['id']]['features'],'source_files_checked':0,'source_equals_crate':True,'source_markers':[],'excerpts':[]}
    with tarfile.open(archive,'r:gz') as tar:
        # Verify every Rust source file and normalized Cargo.toml read for this inventory.
        for member in tar.getmembers():
            relative=Path(member.name).relative_to(prefix)
            if not member.isfile() or not (str(relative).startswith('src/') and relative.suffix=='.rs' or str(relative)=='Cargo.toml'):continue
            data=tar.extractfile(member).read()
            local=cache/'src'/index/prefix/relative
            assert local.read_bytes()==data,(name,relative)
            row['source_files_checked']+=1
            if relative.suffix=='.rs':
                for number,line in enumerate(data.decode().splitlines(),1):
                    if re.search(r'impl.*\b(?:Drop|Zeroize|ZeroizeOnDrop)\b',line):
                        row['source_markers'].append({'file':str(relative),'line':number,'text':line})
        for file,ranges in files.items():
            data=tar.extractfile(prefix+'/'+file).read()
            lines=data.decode().splitlines()
            for start,end in ranges:
                excerpt.append(f'\n{prefix}/{file}:{start}-{end}\n'+'\n'.join(f'{n}: {lines[n-1]}' for n in range(start,end+1))+'\n')
                row['excerpts'].append({'file':file,'start':start,'end':end,'whole_file_sha256':hashlib.sha256(data).hexdigest()})
    report['packages'].append(row)
(out/'inventory.json').write_text(json.dumps(report,indent=2)+'\n')
(out/'source-excerpts.txt').write_text('Official crates.io locked sources; small excerpts for state-lifetime review.\n'+''.join(excerpt))
print(json.dumps({'verified_packages':len(report['packages']),'source_files':sum(p['source_files_checked'] for p in report['packages'])}))
