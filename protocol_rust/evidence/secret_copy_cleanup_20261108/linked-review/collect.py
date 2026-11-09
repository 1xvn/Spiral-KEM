from pathlib import Path
import hashlib,json,re,subprocess
out=Path('/workspace/secret-copy-linked-review')
binary=Path('/workspace/secret-copy-standalone-local/build/audit/deps/spiral_protocol-4ed2cea9ed487504')
source=Path('/tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((source/'SOURCE.json').read_text())
for name,h in manifest['files'].items():assert digest(source/name)==h,name
identity={'source_commit':manifest['source_commit'],'source_files_verified':len(manifest['files']),'source_manifest_sha256':digest(source/'SOURCE.json'),'binary_sha256':digest(binary),'binary_bytes':binary.stat().st_size}
raw=subprocess.check_output(['nm','-S','--defined-only','--no-demangle',str(binary)],text=True)
demangled=subprocess.check_output(['nm','-S','--defined-only','--demangle',str(binary)],text=True)
(out/'nm-defined-raw.txt').write_text(raw);(out/'nm-defined-demangled.txt').write_text(demangled)
(out/'elf-headers.txt').write_text(subprocess.check_output(['readelf','-hWl',str(binary)],text=True))
rows={}
for line in raw.splitlines():
 parts=line.split(None,3)
 if len(parts)==4:
  try:address=int(parts[0],16);size=int(parts[1],16)
  except ValueError:continue
  rows[address]={'address':address,'size':size,'symbol':parts[3]}
for line in demangled.splitlines():
 parts=line.split(None,3)
 if len(parts)==4:
  try:address=int(parts[0],16)
  except ValueError:continue
  if address in rows:rows[address]['demangled']=parts[3]
selectors=[
 ('digest-sha256-full-res',lambda s:'CtOutWrapper<sha2::block_api::Sha256VarCore' in s and 'finalize_fixed_core' in s),
 ('digest-sha512-full-res',lambda s:'CtOutWrapper<sha2::block_api::Sha512VarCore' in s and 'finalize_fixed_core' in s),
 ('hmac-finalize',lambda s:s.startswith('<hmac::Hmac<sha2::Sha256> as digest::FixedOutput>::finalize_fixed')),
 ('hmac-constructor',lambda s:s.startswith('<hkdf::GenericHkdf<hmac::Hmac<sha2::Sha256>>>::from_prk')),
 ('hkdf-expand',lambda s:s.startswith('<hkdf::GenericHkdf<hmac::Hmac<sha2::Sha256>>>::expand_multi_info')),
 ('hkdf-extract',lambda s:s.startswith('<hkdf::GenericHkdf<hmac::Hmac<sha2::Sha256>>>::extract')),
 ('hkdf-output-drop',lambda s:s.startswith('core::ptr::drop_glue::<hkdf::secret_bytes::SecretBytes<')),
 ('hkdf-previous-block-drop',lambda s:s.startswith('core::ptr::drop_glue::<core::option::Option<hkdf::secret_bytes::SecretBytes<')),
 ('ed-seed-digest',lambda s:s.startswith('<ed25519_dalek::hazmat::ExpandedSecretKey as core::convert::From<&[u8; 32]>>::from')),
 ('ed-expanded-key',lambda s:s.startswith('<ed25519_dalek::hazmat::ExpandedSecretKey>::from_bytes')),
 ('ed-production-sign',lambda s:s.startswith('<spiral_protocol::identity::ServerIdentity>::sign')),
 ('curve-nonce-hash',lambda s:s.startswith('<curve25519_dalek::scalar::Scalar>::from_hash::<sha2::Sha512>')),
 ('curve-nonce-output-drop',lambda s:s.startswith('core::ptr::drop_glue::<curve25519_dalek::secret_scratch::SecretBytes<')),
 ('scalar-zeroize',lambda s:s.startswith('<curve25519_dalek::scalar::Scalar as zeroize::Zeroize>::zeroize'))]
selected=[]
for label,predicate in selectors:
 matched=[r for r in rows.values() if predicate(r.get('demangled',''))]
 assert len(matched)==1,(label,len(matched))
 row=matched[0];text=subprocess.check_output(['objdump','-d','-l','--inlines','--demangle','--start-address='+hex(row['address']),'--stop-address='+hex(row['address']+row['size']),str(binary)],text=True)
 (out/(label+'.asm')).write_text(text)
 assert re.search(r'^\s*[0-9a-f]+:\s+',text,re.M),(label,'no instructions')
 # Consecutive source/inline lines preceding each machine instruction form its
 # DWARF context. Preserve all selected instructions in the .asm files.
 context=[];instructions=[]
 for line in text.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+(?:(?:[0-9a-f]{2})\s+)+\s*(.*)',line)
  if m:
   if m[2]:instructions.append({'rva':int(m[1],16),'asm':m[2],'context':context[:]})
   context=[]
  elif line.strip():context.append(line)
 selected.append({**row,'label':label,'file':label+'.asm','instructions':instructions,'disassembly_sha256':digest(out/(label+'.asm'))})
(out/'selected-functions.json').write_text(json.dumps({'identity':identity,'functions':[{k:v for k,v in row.items() if k!='instructions'} for row in selected]},indent=2)+'\n')
# Keep parsed records outside the repository for focused source-context review.
(out/'parsed-instructions.json').write_text(json.dumps(selected,indent=2)+'\n')
for name,h in manifest['files'].items():assert digest(source/name)==h,name
assert digest(binary)==identity['binary_sha256']
print(json.dumps({'identity':identity,'selected_functions':len(selected),'disassembly_bytes':sum((out/r['file']).stat().st_size for r in selected)},indent=2))
