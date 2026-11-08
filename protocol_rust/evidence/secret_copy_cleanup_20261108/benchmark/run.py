from pathlib import Path
import collections,datetime,hashlib,json,os,platform,statistics,subprocess,time,tomllib
root=Path('/workspace/secret-copy-benchmark')
repo=Path('/workspace/spiral-secret-copy-cleanup-20261108')
variants=['baseline','candidate']
binaries={v:root/(v+'-target/release/spiral-secret-copy-benchmark') for v in variants}
for p in binaries.values():assert p.is_file(),p
cpu=max(os.sched_getaffinity(0))
meta={'system':platform.uname()._asdict(),'affinity_available':sorted(os.sched_getaffinity(0)),'benchmark_cpu':cpu,'repetitions':7,'case_warmup_operations':100,'profile':{'opt_level':3,'lto':'thin','codegen_units':1,'panic':'unwind'},'flags':{k:os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS']},'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'loadavg_start':os.getloadavg(),'binary_sha256':{v:hashlib.sha256(p.read_bytes()).hexdigest() for v,p in binaries.items()},'compiler':subprocess.check_output(['/workspace/rust48-tools/rust/bin/rustc','-Vv'],text=True)}
info=Path('/proc/cpuinfo').read_text()
meta['cpu_description']=next((line.split(':',1)[1].strip() for line in info.splitlines() if line.startswith('model name')),'unknown')
versions={}
for v in variants:
 d=tomllib.loads((root/v/'Cargo.lock').read_text());versions[v]=sorted((p['name'],p['version']) for p in d['package'] if p['name']!='spiral-secret-copy-benchmark')
assert versions['baseline']==versions['candidate'],versions
meta['package_versions_identical']=True
meta['package_versions']=versions['baseline']
rows=[]
for trial in range(meta['repetitions']):
 order=variants if trial%2==0 else list(reversed(variants))
 for v in order:
  start=time.time()
  done=subprocess.run(['taskset','-c',str(cpu),str(binaries[v])],capture_output=True,text=True,check=True)
  (root/f'trial-{trial:02d}-{v}.jsonl').write_text(done.stdout)
  (root/f'trial-{trial:02d}-{v}.stderr').write_text(done.stderr)
  assert not done.stderr
  sample=[json.loads(line) for line in done.stdout.splitlines()]
  assert len(sample)==21
  for row in sample:row.update(trial=trial,variant=v,process_started_epoch=start)
  rows.extend(sample)
  print(json.dumps({'trial':trial,'variant':v,'cases':len(sample)}),flush=True)
(root/'raw-samples.json').write_text(json.dumps(rows,indent=2)+'\n')
groups=collections.defaultdict(dict)
for row in rows:groups[(row['operation'],row['input_bytes'])].setdefault(row['variant'],[]).append(row)
summary=[]
for key,variant in sorted(groups.items()):
 outputs={r['public_output_hex'] for rs in variant.values() for r in rs};assert len(outputs)==1,key
 item={'operation':key[0],'input_bytes':key[1],'public_outputs_identical':True}
 med={}
 for v in variants:
  times=[r['ns_per_op'] for r in variant[v]]
  med[v]=statistics.median(times)
  item[v]={'median_ns_per_op':med[v],'min_ns_per_op':min(times),'max_ns_per_op':max(times),'samples_ns_per_op':times}
 item['candidate_to_baseline_median_ratio']=med['candidate']/med['baseline']
 summary.append(item)
meta['loadavg_finish']=os.getloadavg();meta['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
after={}
for name in ['digest','hmac','hkdf','ed25519-dalek','curve25519-dalek']:
 base=repo/'third_party/rustcrypto'/name
 for p in sorted(base.rglob('*')):
  if p.is_file() and (p.suffix=='.rs' or p.name=='Cargo.toml'):
   after[str(p.relative_to(repo))]=hashlib.sha256(p.read_bytes()).hexdigest()
before=json.loads((root/'candidate-source-before.json').read_text())
meta['candidate_source_unchanged_during_build_and_measurement']=before==after
meta['source_hash_differences']=[p for p in sorted(set(before)|set(after)) if before.get(p)!=after.get(p)]
(root/'candidate-source-after.json').write_text(json.dumps(after,indent=2)+'\n')
report={'metadata':meta,'cases':summary,'interpretation':{'scope':'Warm-cache microbenchmarks on one pinned local CPU, not end-to-end service/TLS latency or peak-memory testing.','shared_environment':True,'deployment_performance_approved':False,'absolute_overheads':'The same stack output normalization and black_box overhead are included in both variants.','no_security_approval_implied':True}}
(root/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'output':str(root/'result.json'),'cases':len(summary),'samples':len(rows),'all_public_outputs_identical':True,'source_unchanged':meta['candidate_source_unchanged_during_build_and_measurement']}),flush=True)
