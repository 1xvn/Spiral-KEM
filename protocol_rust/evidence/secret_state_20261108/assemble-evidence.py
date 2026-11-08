"""Verify and preserve completed public-fixture measurements; never rerun them."""
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib

ROOT=Path('/workspace/Spiral-KEM');sys.path.insert(0,str(ROOT))
from protocol_rust.diagnostics.receive_flow import inspect_log
work=Path('/workspace/secret-state-upgrade-20261108')
out=ROOT/'protocol_rust/evidence/secret_state_20261108'
out.mkdir(exist_ok=False)
commit='fe52b62a146850927bcc62c09395adac3fcaafb2'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(name,value):(out/name).write_text(json.dumps(value,indent=2)+'\n')
def copy(source,target):
    destination=out/target;destination.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,destination);assert sha(Path(source))==sha(destination)
def archive(path):
    with tarfile.open(path,'r:gz') as tar:
        members=tar.getmembers();assert len({m.name for m in members})==len(members)
        assert all(not m.issym() and not m.islnk() and '..' not in Path(m.name).parts and not Path(m.name).is_absolute() for m in members)
        manifests=[m for m in members if m.name.endswith('/SHA256.json')];assert len(manifests)==1
        prefix=str(Path(manifests[0].name).parent);hashes=json.load(tar.extractfile(manifests[0]))
        for name,value in hashes.items():assert hashlib.sha256(tar.extractfile(prefix+'/'+name).read()).hexdigest()==value
    return {'sha256':sha(path),'manifest_files_verified':len(hashes)}

rx=json.loads((work/'receive-flow/result.json').read_text())
assert rx['git_commit']==commit and rx['diagnostic_complete'] and rx['instruction_mapping_complete'] and rx['binary_and_source_unchanged']
assert rx['counts']=={'fixture_variants':78,'public_baselines':78,'key_prefix_taint_traces':78,'positive_controls':2}
source=rx['source_sha256']|{p:sha(ROOT/p) for p in ('ci/validate.py','protocol_rust/diagnostics/receive_flow.py','protocol_rust/diagnostics/libtest_memory.py','protocol_rust/diagnostics/test_receive_flow.py')}
for name,value in source.items():
    blob=subprocess.check_output(['git','show',commit+':'+name],cwd=ROOT)
    assert hashlib.sha256(blob).hexdigest()==sha(ROOT/name)==value,name
assert rx['runner_sha256']==sha(ROOT/'protocol_rust/diagnostics/receive_flow.py')
binary=Path(rx['binary']['path']);assert sha(binary)==rx['binary']['sha256']
review={'code_commit':commit,'source_sha256_verified_against_git_blob':source,
 'binary_sha256':sha(binary),'binary_unchanged':True,'constant_time_approved':False,'production_memory_passed':False,
 'all_temporary_secrets_erased':False,'original_memory_findings_resolved':False,
 'receive':{'counts':rx['counts'],'diagnostic_complete':True,'instruction_mapping_complete':True,
   'warning_contexts':dict(Counter(w['classification'] for c in rx['cases'] for w in c['warnings'])),
   'raw_exits':dict(Counter(c['exit'] for c in rx['cases']+rx['positive_controls'])),
   'possibly_lost_48_block_counts':dict(Counter(c['leaks']['possibly lost']['blocks'] for c in rx['cases']+rx['positive_controls']))},
 'taint_and_wipe':[]}
assert 'unclassified' not in review['receive']['warning_contexts']
for row in json.loads((work/'taint-and-wipe/process.json').read_text()):
    parsed,warnings=inspect_log((work/'taint-and-wipe'/(row['name']+'.log')).read_text(),row['raw_exit'])
    assert not warnings and parsed['summary']['errors']==1 and row['binary_sha256']==sha(binary)
    stdout=(work/'taint-and-wipe'/(row['name']+'.stdout')).read_text()
    assert ('1 passed; 0 failed;' if row['name']=='kdf-seal-sign' else '4 passed; 0 failed;') in stdout
    assert not (work/'taint-and-wipe'/(row['name']+'.stderr')).read_bytes()
    review['taint_and_wipe'].append({**row,**parsed,'branch_or_address_contexts':0})
for path in (work/'taint-and-wipe').iterdir():copy(path,'taint-and-wipe/'+path.name)
for name in ('receive-flow','record-fuzz'):
    path=work/(name+'.tar.gz');review[name]=archive(path);copy(path,name+'.tar.gz')
fuzz=json.loads((work/'record-fuzz/result.json').read_text());assert fuzz['status']=='passed'
assert all(sha(ROOT/name)==value for name,value in fuzz['source_sha256'].items())
review['record_fuzz']=[{key:t[key] for key in ('name','status','feedback','differential')} for t in fuzz['targets']]
functional=json.loads((work/'functional/result.json').read_text());assert functional['status']=='passed'
assert all(c['passed'] for c in functional['checks'])
review['functional']={c['name']:{k:v for k,v in c.items() if k in ('exit','passed','tests_run','test_groups','structured_tests')} for c in functional['checks']}
for path in (work/'functional').iterdir():copy(path,'functional/'+path.name)
for name in ('audit-build.jsonl','audit-binary.json','asan-build.jsonl','asan-tests.log','stable-tests.log',
 'state-tests-optimized.log','cargo-update.log','fuzz-lock-update.log','sha2-features.txt','sha2-fuzz-features.txt',
 'probe-disabled.log','probe-enabled.log','probe-result.json','linked-state-symbols.txt','old-sha2-public-build-tree.txt'):
    copy(work/name,name)
for path in (work/'probe').rglob('*'):
    if path.is_file():copy(path,'probe/'+str(path.relative_to(work/'probe')))
asan=(work/'asan-tests.log').read_text()
assert '70 passed; 0 failed; 5 ignored;' in asan and '"pairs_checked":40' in asan
assert not re.search(r'(?:ERROR|SUMMARY):\s*(?:AddressSanitizer|LeakSanitizer)|LeakSanitizer has encountered|Sanitizer CHECK failed',asan)
rows=[]
for line in (work/'asan-build.jsonl').read_text().splitlines():
    try:rows.append(json.loads(line))
    except ValueError:pass
executables=[r['executable'] for r in rows if r.get('reason')=='compiler-artifact' and r.get('target',{}).get('name')=='spiral_protocol' and r.get('profile',{}).get('test') and r.get('executable')]
assert len(executables)==1
symbols=subprocess.check_output(['readelf','-Ws',executables[0]],text=True);assert '__asan_init' in symbols
review['asan']={'passed':True,'tests_passed':70,'ignored':5,'binary_sha256':sha(Path(executables[0])),
 'asan_init_present':True,'rustc':subprocess.check_output(['/workspace/rust-parser-tools/installer-verified/bin/rustc','-Vv'],text=True),
 'rustflags':'-Zsanitizer=address -Cdebuginfo=1 -Cforce-frame-pointers=yes -Coverflow-checks=yes -Cdebug-assertions=yes',
 'asan_options':'detect_leaks=1:abort_on_error=1','prebuilt_std_and_native_openssl_coverage_claimed':False}
probe=json.loads((work/'probe-result.json').read_text());assert [r['exit'] for r in probe]==[101,0]
review['feature_negative_and_positive_controls']=probe
text=(work/'linked-state-disassembly.txt').read_text();lines=text.splitlines();excerpts=[]
for marker in ('sha2-0.11.1/src/block_api.rs:97','sha2-0.11.1/src/block_api.rs:222'):
    index=next(i for i,line in enumerate(lines) if marker in line)
    nearby='\n'.join(lines[max(0,index-4):index+14])
    assert re.search(r'mov[lq]\s+\$0x0,',nearby)
    excerpts.append(marker+'\n'+nearby+'\n')
(out/'linked-cleanup-excerpts.txt').write_text('\n'.join(excerpts))
(out/'linked-state-disassembly.txt.gz').write_bytes(gzip.compress(text.encode(),mtime=0))
review['linked_cleanup']={'binary_sha256':sha(binary),'uncompressed_disassembly_sha256':sha(work/'linked-state-disassembly.txt'),
 'sha256_hmac_hkdf_and_sha512_signer_volatile_zero_stores_present':True,'all_copies_or_registers_wiped':False}

# Verify every newly added/updated, active target dependency's original crate and sources.
env=dict(os.environ,CARGO_HOME='/workspace/rust48-tools/cargo-cache',CARGO_NET_OFFLINE='true',RUSTC='/workspace/rust48-tools/rust/bin/rustc')
meta=json.loads(subprocess.check_output(['/workspace/rust48-tools/rust/bin/cargo','metadata','--locked','--offline','--filter-platform','x86_64-unknown-linux-gnu','--format-version=1','--manifest-path',str(ROOT/'protocol_rust/Cargo.toml')],env=env))
nodes={r['id']:r for r in meta['resolve']['nodes']};packages={(r['name'],r['version']):r for r in meta['packages']}
old=tomllib.loads(subprocess.check_output(['git','show','d083dde:protocol_rust/Cargo.lock'],cwd=ROOT).decode())
new=tomllib.loads((ROOT/'protocol_rust/Cargo.lock').read_text())
old_keys={(p['name'],p['version']) for p in old['package']}
added=[p for p in new['package'] if (p['name'],p['version']) not in old_keys]
cache=Path('/workspace/rust48-tools/cargo-cache/registry');index='index.crates.io-1949cf8c6b5b557f'
inventory=[]
for p in added:
    key=p['name'],p['version'];prefix='-'.join(key);package=packages.get(key)
    if package is None:
        inventory.append({'name':p['name'],'version':p['version'],'checksum_in_lock':p['checksum'],'selected_for_current_target':False});continue
    crate=cache/'cache'/index/(prefix+'.crate');assert sha(crate)==p['checksum']
    checked=0
    with tarfile.open(crate,'r:gz') as tar:
        for member in tar.getmembers():
            relative=Path(member.name).relative_to(prefix)
            if not member.isfile() or not (str(relative).startswith('src/') and relative.suffix=='.rs' or str(relative)=='Cargo.toml'):continue
            assert (cache/'src'/index/prefix/relative).read_bytes()==tar.extractfile(member).read()
            checked+=1
    inventory.append({'name':p['name'],'version':p['version'],'selected_for_current_target':True,
      'crate_sha256_matches_lock':True,'crate_sha256':sha(crate),'source_files_verified':checked,'features':nodes[package['id']]['features']})
for manifest in ('protocol_rust/Cargo.lock','protocol_rust/fuzz/Cargo.lock'):
    locked=tomllib.loads((ROOT/manifest).read_text())
    for p in added:assert any(r['name']==p['name'] and r['version']==p['version'] and r.get('checksum')==p.get('checksum') for r in locked['package'])
review['dependency_inventory']=inventory
assert any(p['name']=='sha2' and p['version']=='0.11.1' and 'zeroize' in p['features'] for p in inventory)
assert any(p['name']=='hmac' and 'zeroize' in p['features'] for p in inventory)
dalek=next(p for p in meta['packages'] if p['name']=='ed25519-dalek')
sha_dependencies=[d['pkg'] for d in nodes[dalek['id']]['deps'] if d['name']=='sha2']
assert len(sha_dependencies)==1 and sha_dependencies[0].endswith('sha2@0.11.1')
review['dalek_uses_same_zeroize_sha2_0_11_1']=True
ranges={
 'sha2-0.11.1':{'src/block_api.rs':[(92,104),(217,228)]},
 'block-buffer-0.12.1':{'src/lib.rs':[(424,442)]},
 'hmac-0.13.0':{'src/block_api.rs':[(14,26),(56,69),(84,94)],'src/utils.rs':[(15,33)]},
 'hkdf-0.13.0':{'src/lib.rs':[(130,171)]},
 'digest-0.11.3':{'src/buffer_macros/fixed.rs':[(464,484)]},
 'ed25519-dalek-3.0.0':{'src/signing.rs':[(718,726),(863,869),(914,936)],'src/hazmat.rs':[(84,95)]},
 'curve25519-dalek-5.0.0':{'src/scalar.rs':[(192,202),(548,555),(663,670)]}}
source_excerpts=[]
for prefix,files in ranges.items():
    for file,parts in files.items():
        path=cache/'src'/index/prefix/file;lines=path.read_text().splitlines()
        for start,end in parts:
            end=min(end,len(lines));assert 1<=start<=end
            source_excerpts.append(prefix+'/'+file+f':{start}-{end}\n'+'\n'.join(f'{i}: {lines[i-1]}' for i in range(start,end+1))+'\n')
(out/'dependency-source-excerpts.txt').write_text('Locked official crates.io sources; limited excerpts for cleanup and remaining lifetime gaps.\n\n'+'\n'.join(source_excerpts))
artifact_rows=[]
for line in (work/'audit-build.jsonl').read_text().splitlines():
    try:r=json.loads(line)
    except ValueError:continue
    if r.get('reason')=='compiler-artifact' and any(r.get('package_id','').endswith(p['name']+'@'+p['version']) for p in added):artifact_rows.append(r)
save('selected-compiler-artifacts.json',artifact_rows)
save('review.json',review)
copy(Path(__file__),'assemble-evidence.py')
print(json.dumps({'receive':review['receive'],'added_dependencies':len(added),
 'verified_target_dependencies':sum(p['selected_for_current_target'] for p in inventory),'source_files':sum(p.get('source_files_verified',0) for p in inventory)}))
