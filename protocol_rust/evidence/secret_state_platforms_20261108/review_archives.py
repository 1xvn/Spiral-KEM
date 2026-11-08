"""Read-only review of fixed-source OCI/WSL functional evidence.

No uploaded file is executed or extracted. Hashes attest archive consistency,
not a trusted signature by the remote host or a complete security assessment.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

COMMIT='fcf7ff07ecba260f6b446baa7f1efd55bbe11ec2'
SOURCE={'commit':COMMIT,
 'manifest_sha256':'29944b7d762c2e94f5bb6f9dfebcefbcd326ac1eaafe4af0ebc659dc40bbc146',
 'files_verified':603,
 'runner_sha256':'7a796ec038db018367bf3f5861e67cfc0ee4a90ffbe37c338cccbe417e0d8151',
 'cargo_lock_sha256':'d12949c1b2e3293041b75d0461e94ed133a6a78635a2cfb85c9710be02a603d2'}
LAUNCHER='e06f4ca155d44acebf3a8246795e47c70dbab3105ecbe917a5729a9d38b766f3'
COMPILER='58cf8f9c35b355199727627d07ae34a4e2846d67'
COUNTS={'python-protocol':85,'diagnostic-parser':20,'native-kem':9,'rust-unit':70,'rust-doc':6,'rust-tls':35}
DEPENDENCIES={'hmac':'0.13.0','hkdf':'0.13.0','sha2':'0.11.1','ed25519-dalek':'3.0.0','curve25519-dalek':'5.0.0'}


def require(condition,message):
    if not condition:raise ValueError(message)


def digest(data):return hashlib.sha256(data).hexdigest()


def decode(data):
    def pairs(rows):
        result={}
        for key,value in rows:
            if key in result:raise ValueError('duplicate JSON key: '+key)
            result[key]=value
        return result
    return json.loads(data,object_pairs_hook=pairs)


def review(path,label):
    with tarfile.open(path,'r:gz') as tar:
        members=tar.getmembers()
        require(len(members)<=256 and sum(m.size for m in members)<=32*1024*1024,'archive limits exceeded')
        require(len({m.name for m in members})==len(members),'duplicate archive member')
        require(all((m.isfile() or m.isdir()) and not PurePosixPath(m.name).is_absolute()
          and '..' not in PurePosixPath(m.name).parts for m in members),'unsafe member')
        files={m.name:m for m in members if m.isfile()}
        manifests=[name for name in files if name.endswith('/SHA256.json')]
        require(len(manifests)==1,'expected one archive manifest')
        prefix=manifests[0][:-len('/SHA256.json')]
        def read(name):
            member=files.get(prefix+'/'+name)
            require(member is not None and member.size<=4*1024*1024,'missing or oversized file: '+name)
            return tar.extractfile(member).read()
        manifest=decode(read('SHA256.json'))
        require(set(files)=={prefix+'/'+name for name in manifest}|{prefix+'/SHA256.json'},'missing or unlisted archive file')
        for name,value in manifest.items():require(digest(read(name))==value,'hash mismatch: '+name)
        result=decode(read('result.json'));functional=decode(read('functional/result.json'))
        require(result['status']==functional['status']=='passed' and not result['errors'],'reported failure')
        require(result['requested_environment']==label,'environment label differs')
        require(result['source_verified'] is True and result['source_unchanged'] is True,'source check incomplete')
        require(result['source']==SOURCE and result['source_commit']==COMMIT,'source record differs from fixed bundle')
        require(result['launcher_sha256']==LAUNCHER,'launcher differs')
        require(all(row['exit']==0 for row in result['commands']),'launcher command failed')
        checks={row['name']:row for row in functional['checks']}
        require(len(checks)==len(functional['checks']) and len(checks)==9,'incomplete functional check set')
        require(all(row['exit']==0 and row['passed'] is True for row in checks.values()),'functional command failed')
        require(functional['runner_sha256']==SOURCE['runner_sha256'],'CI runner differs')
        require(functional['cargo_lock_sha256']==SOURCE['cargo_lock_sha256'],'Cargo.lock differs')
        for name in ('python-protocol','diagnostic-parser','native-kem','rust-tls'):
            text=read('functional/'+name+'.log').decode()
            counts=re.findall(r'Ran (\d+) tests? in ',text)
            require(counts==[str(COUNTS[name])] and re.search(r'(?m)^OK\s*$',text),'unittest output differs: '+name)
            require(checks[name]['tests_run']==COUNTS[name],'unittest report differs: '+name)
        ignored=0 if label=='oci' else 5
        for name,expected_ignored in (('rust-unit',ignored),('rust-doc',0)):
            groups=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',read('functional/'+name+'.log').decode())
            require(groups==[(str(COUNTS[name]),'0',str(expected_ignored))],'Rust output differs: '+name)
            require(checks[name]['test_groups']==[{'passed':COUNTS[name],'failed':0,'ignored':expected_ignored}],'Rust report differs: '+name)
        platform=result['platform'];machine='aarch64' if label=='oci' else 'x86_64'
        require(platform['system']=='Linux' and platform['machine']==machine,'platform differs')
        require(label!='wsl' or 'microsoft' in platform['release'].lower(),'WSL kernel not recorded')
        version=read('functional/rustc-version.log').decode()
        require('release: 1.99.1\n' in version and 'commit-hash: '+COMPILER+'\n' in version
          and 'host: '+machine+'-unknown-linux-gnu\n' in version,'wrong Rust compiler')
        require(read('functional/cargo-version.log').decode().startswith('cargo 1.99.1 '),'wrong Cargo version')
        tls=decode(read('functional/interop.json'))
        require(tls['tests']==35 and tls['failures']==tls['errors']==0,'TLS report differs')
        require(checks['rust-tls']['structured_tests']=={'tests':35,'failures':0,'errors':0},'TLS CI summary differs')
        build=read('functional/rust-unit.log').decode()
        for name,version in DEPENDENCIES.items():
            require(re.search(r'Compiling '+re.escape(name)+r' v'+re.escape(version)+r'(?:\s|$)',build),'new dependency compilation not recorded: '+name)
        require(result['memory_checked'] is False and functional['memory_checked'] is False
          and result['constant_time_approved'] is False and functional['constant_time_approved'] is False,'scope flags differ')
        return {'environment':label,'functional_accepted':True,'archive':path.name,
          'archive_sha256':digest(path.read_bytes()),'manifest_files_verified':len(manifest),
          'source_verification_record':result['source'],'launcher_sha256':result['launcher_sha256'],
          'platform':platform,'rustc_verbose':read('functional/rustc-version.log').decode(),
          'python_version':read('python-version.log').decode().strip(),
          'python_dependencies':read('pinned-requirements.log').decode().strip(),
          'counts':COUNTS,'ignored_taint_tests':ignored,'compiled_crypto_dependencies':DEPENDENCIES,
          'binary_sha256':functional['binary_sha256'],'started_utc':result['started_utc'],'finished_utc':result['finished_utc'],
          'commands_exit_zero':True,'source_unchanged_recorded':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oci',type=Path,required=True)
    parser.add_argument('--wsl',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report={'schema':'spiral-secret-state-platform-review/v1','source_commit':COMMIT,
      'reviewer_sha256':digest(Path(__file__).read_bytes()),
      'reviewed_utc':datetime.now(timezone.utc).isoformat(),'both_platforms_functional_complete':False,
      'whole_memory_approved':False,'constant_time_approved':False,'cryptographic_security_approved':False,
      'archive_files_executed':False,'archive_files_extracted':False,
      'provenance_limit':'Source verification is recorded by the hash-matched supplied launcher; the uploaded reports do not include all source files or a trusted remote-host signature.',
      'environments':[],'errors':[]}
    try:
        report['environments']=[review(args.oci,'oci'),review(args.wsl,'wsl')]
        require(report['environments'][0]['source_verification_record']==report['environments'][1]['source_verification_record'],'platform source records differ')
        report['both_platforms_functional_complete']=True
    except Exception as error:
        report['errors'].append(str(error))
    with args.output.open('x') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'both_platforms_functional_complete':report['both_platforms_functional_complete'],'errors':report['errors']}))
    return 0 if report['both_platforms_functional_complete'] else 1


if __name__=='__main__':raise SystemExit(main())
