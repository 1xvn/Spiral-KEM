"""Assemble already completed public-fixture measurements without rewriting logs."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tomllib

root=Path('/workspace/Spiral-KEM');sys.path.insert(0,str(root))
from protocol_rust.diagnostics.receive_flow import inspect_log
base=root/'protocol_rust/evidence/receive_flow_20261108'
base.mkdir(exist_ok=False)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def copy(source,destination):
    target=base/destination;target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,target)
    assert sha(Path(source))==sha(target)
def archive_check(path):
    with tarfile.open(path,'r:gz') as tar:
        members=tar.getmembers()
        assert len({m.name for m in members})==len(members)
        for m in members:
            assert not m.issym() and not m.islnk() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
        manifests=[m for m in members if m.name.endswith('/SHA256.json')]
        assert len(manifests)==1
        manifest=manifests[0];prefix=str(Path(manifest.name).parent)
        hashes=json.load(tar.extractfile(manifest))
        for name,value in hashes.items():
            data=tar.extractfile(prefix+'/'+name).read()
            assert hashlib.sha256(data).hexdigest()==value,(path,name)
        return {'manifest_files_verified':len(hashes),'archive_sha256':sha(path)}

commit='832e996842b2d0c746dd7b65e388907207c5b72c'
rx=json.loads(Path('/workspace/receive-flow-20261108/result.json').read_text())
assert rx['git_commit']==commit and rx['diagnostic_complete'] and rx['instruction_mapping_complete'] and rx['binary_and_source_unchanged']
assert rx['counts']=={'fixture_variants':78,'public_baselines':78,'key_prefix_taint_traces':78,'positive_controls':2}
paths=rx['source_sha256']|{p:sha(root/p) for p in ('protocol_rust/diagnostics/receive_flow.py','protocol_rust/diagnostics/libtest_memory.py','protocol_rust/diagnostics/test_receive_flow.py')}
for name,value in paths.items():
    data=subprocess.check_output(['git','show',commit+':'+name],cwd=root)
    assert hashlib.sha256(data).hexdigest()==value==sha(root/name),name
assert rx['runner_sha256']==sha(root/'protocol_rust/diagnostics/receive_flow.py')
assert rx['binary']['sha256']==sha(Path(rx['binary']['path']))
assert not rx['declassification_used'] and not rx['suppression_used'] and not rx['production_memory_passed'] and not rx['constant_time_approved']
review={'code_commit':commit,'measurement_source_matches_git_blob':True,'source_sha256_verified':paths,
 'runner_and_parser_match_committed_source':True,'binary_unchanged_after_measurement':True,
 'diagnostic_complete':True,'instruction_mapping_complete':True,'constant_time_approved':False,
 'production_memory_passed':False,'original_48_byte_finding_resolved':False,
 'declassification_used':False,'suppression_used':False,'counts':rx['counts'],'by_mode':[],
 'raw_memcheck_exits':dict(Counter(c['exit'] for c in rx['positive_controls']+rx['cases']))}
for mode in sorted({c['parameters']['mode'] for c in rx['cases']}):
    for taint in ('public','secret'):
        rows=[r for r in rx['cases'] if r['parameters']['mode']==mode and r['taint']==taint]
        categories=Counter(w['classification'] for row in rows for w in row['warnings'])
        assert not categories.get('unclassified')
        assert all(row['leaks']['possibly lost'] in ({'bytes':48,'blocks':1},{'bytes':0,'blocks':0}) for row in rows)
        review['by_mode'].append({'mode':mode,'taint':taint,'fixtures':len(rows),'warning_contexts':dict(categories),
          'possibly_lost_byte_counts':dict(Counter(row['leaks']['possibly lost']['bytes'] for row in rows))})
review['actual_receive_unclassified_warning_contexts']=0
review['actual_receive_warning_contexts']=sum(len(c['warnings']) for c in rx['cases'])
review['positive_controls']=[{'kind':c['kind'],'exit':c['exit'],'warnings':c['warnings']} for c in rx['positive_controls']]
for stem in ('receive-flow-20261108','receive-flow-record-fuzz-20261108'):
    original=Path('/workspace')/(stem+'.tar.gz')
    review[stem]=archive_check(original)
    copy(original,stem+'.tar.gz')

functional=Path('/workspace/receive-flow-functional-final-20261108')
fr=json.loads((functional/'result.json').read_text());assert fr['status']=='passed' and all(c['passed'] for c in fr['checks'])
review['functional']={c['name']:{k:v for k,v in c.items() if k in ('exit','passed','tests_run','test_groups','structured_tests')} for c in fr['checks']}
for path in functional.iterdir():copy(path,'functional/'+path.name)
copy(root/'ci/validate.py','functional/validate.py')
for source,label in (
 ('/workspace/receive-audit-build-20261108.log','audit-build.jsonl'),
 ('/workspace/receive-audit-native-20261108.log','receive-stable-debug.log'),
 ('/workspace/receive-flow-public-asan-20261108.log','receive-asan.log'),
 ('/workspace/receive-flow-wipe-asan-20261108.log','wipe-asan.log'),
 ('/workspace/receive-flow-wipe-optimized-20261108.log','wipe-optimized.log'),
 ('/workspace/receive-flow-diagnostic-tests-20261108.log','diagnostic-gates.log'),
 ('/workspace/receive-flow-ci-tests-20261108.log','ci-gates.log')):
    copy(source,label)
wipe=Path('/workspace/receive-flow-wipe-memcheck-20261108')
for path in wipe.iterdir():copy(path,'wipe-memcheck/'+path.name)
parsed,warnings=inspect_log((wipe/'memcheck.log').read_text(),json.loads((wipe/'process.json').read_text())['exit'])
assert not warnings and parsed['summary']['errors']==1
review['wipe_memcheck']={**parsed,'raw_exit':99,'memory_passed':False}
for filename in ('before-artifact.json','after-artifact.json','before.log','after.log','drop.rs'):
    copy('/workspace/poly1305-drop-proof-20261108/'+filename,'poly1305/'+filename)
for label in ('before','after'):
    artifact=json.loads((base/f'poly1305/{label}-artifact.json').read_text())
    review['poly1305_'+label]={'features':artifact['features'],
      'artifact_sha256':{name:sha(Path(name)) for name in artifact['filenames']},
      'result':(base/f'poly1305/{label}.log').read_text().strip()}
for source,name in (('poly1305-features-before.txt','features-before.txt'),('poly1305-features-after.txt','features-after.txt'),('poly1305-fuzz-features-after.txt','fuzz-features-after.txt')):
    copy('/workspace/'+source,'poly1305/'+name)
for path in Path('/workspace/receive-dependency-inventory-20261108').iterdir():copy(path,'dependencies/'+path.name)
copy('/workspace/receive-dependency-inventory.py','dependencies/inventory-builder.py')
review['dependencies']=json.loads((base/'dependencies/inventory.json').read_text())
for lockname in ('protocol_rust/Cargo.lock','protocol_rust/fuzz/Cargo.lock'):
    old=tomllib.loads(subprocess.check_output(['git','show','05d1078:'+lockname],cwd=root).decode())
    new=tomllib.loads((root/lockname).read_text())
    versions=lambda obj:{(p['name'],p['version']):p.get('checksum') for p in obj['package']}
    assert versions(old)==versions(new)
review['dependency_versions_and_checksums_unchanged_from_main']=True
asanbinary=next(Path('/workspace/receive-flow-asan-target/x86_64-unknown-linux-gnu/debug/build/spiral-protocol').rglob('out/spiral_protocol-*'))
symbols=subprocess.check_output(['readelf','-Ws',str(asanbinary)],text=True)
assert '__asan_init' in symbols
review['asan_binary']={'path':str(asanbinary),'sha256':sha(asanbinary),'asan_init_symbol_present':True,
 'rustc':subprocess.check_output(['/workspace/rust-parser-tools/installer-verified/bin/rustc','-Vv'],text=True),
 'rustflags':'-Zsanitizer=address -Cdebuginfo=1 -Cforce-frame-pointers=yes -Coverflow-checks=yes -Cdebug-assertions=yes',
 'asan_options':'detect_leaks=1:abort_on_error=1'}
fuzz=json.loads(Path('/workspace/receive-flow-record-fuzz-20261108/result.json').read_text())
assert fuzz['status']=='passed' and all(fuzz['source_sha256'][p]==sha(root/p) for p in fuzz['source_sha256'])
review['fuzz_targets']=[{k:t[k] for k in ('name','feedback','differential') if k in t} for t in fuzz['targets']]
(base/'review.json').write_text(json.dumps(review,indent=2)+'\n')
copy(Path(__file__),'assemble-evidence.py')
print(json.dumps({'evidence':str(base),'actual_receive_contexts':review['actual_receive_warning_contexts'],
 'raw_exits':review['raw_memcheck_exits'],'manifest_files':{k:v for k,v in review.items() if k.endswith('20261108')}}))
