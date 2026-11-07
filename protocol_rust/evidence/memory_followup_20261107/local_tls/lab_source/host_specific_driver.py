from pathlib import Path
from datetime import datetime,timedelta,timezone
import socket,ssl,subprocess,tempfile,json,re,os,select,sys
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
r=Path('/workspace/scratch/c6a558db7e9f');out=r/'memory_followup_20261107'
vg=r/'rust_setup/vg328/bin/valgrind';loader=r/'spiral_hardening_runs/valgrind_local/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2';lib=loader.parent
binary=out/'tls_probe/target/audit/tls-memory-probe'
variant=sys.argv[1] if len(sys.argv)>1 else 'isolated'
run_dir=out/variant;run_dir.mkdir(exist_ok=True)
result=[]
with tempfile.TemporaryDirectory(prefix='tls-memory-control-') as tmp:
 p=Path(tmp);key=Ed25519PrivateKey.generate();now=datetime.now(timezone.utc)
 subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
 cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False).sign(key,algorithm=None))
 (p/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 (p/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));(p/'key.pem').chmod(0o600)
 for mode in ['aes128','aes256','chacha']:
  log=run_dir/f'{mode}.log'
  cmd=[str(vg),'--error-exitcode=99','--track-origins=yes','--leak-check=full',f'--log-file={log}',str(loader),'--library-path',str(lib),str(binary),str(p/'cert.pem'),str(p/'key.pem'),mode]
  env=os.environ.copy();env['VALGRIND_LIB']=str(r/'rust_setup/vg328/libexec/valgrind')
  proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
  try:
   assert select.select([proc.stdout],[],[],45)[0],'startup timeout'
   first=proc.stdout.readline();assert first,(proc.communicate(timeout=5))
   port=int(first);ctx=ssl.create_default_context(cafile=str(p/'cert.pem'));ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3;ctx.set_alpn_protocols(['memory-probe'])
   with socket.create_connection(('127.0.0.1',port),timeout=20) as sock:
    tls=ctx.wrap_socket(sock,server_hostname='localhost');cipher=tls.cipher()[0]
    tls.sendall(b'D'*120);got=b''
    while len(got)<120:got+=tls.recv(120-len(got))
    assert got==b'D'*120;tls.unwrap().close()
   stdout,stderr=proc.communicate(timeout=30)
   text=log.read_text();m=re.search(r'ERROR SUMMARY: ([\d,]+) errors from ([\d,]+) contexts',text)
   item={'scope':'isolated rustls/tokio control, no Spiral or C KEM','mode':mode,'cipher':cipher,'exit':proc.returncode,'errors':int(m[1].replace(',','')),'contexts':int(m[2].replace(',','')),'stderr':stderr};result.append(item);print(json.dumps(item),flush=True)
  finally:
   if proc.poll() is None:proc.kill();proc.communicate(timeout=5)
(run_dir/'result.json').write_text(json.dumps(result,indent=2)+'\n')
