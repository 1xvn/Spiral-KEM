from pathlib import Path
import json,hashlib
root=Path('/workspace/secret-copy-benchmark')
repo=Path('/workspace/spiral-secret-copy-cleanup-20261108')
source='''use std::{hint::black_box, time::Instant};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use ed25519_dalek::{Signer, SigningKey};

fn hex(data: &[u8]) -> String { data.iter().map(|b|format!("{b:02x}")).collect() }
fn main() {
    let seed = [0x42u8; 32];
    let signing = SigningKey::from_bytes(&seed);
    let lengths = [0usize, 1, 63, 64, 65, 1024, 16384];
    for length in lengths {
        let data = vec![0x5au8; length];
        for operation in ["hmac-sha256", "hkdf-sha256-extract-expand32", "ed25519-sign"] {
            let iterations = match operation { "hmac-sha256" => 20_000, "hkdf-sha256-extract-expand32" => 10_000, _ => 2_000 };
            let execute = || -> Vec<u8> { match operation {
                "hmac-sha256" => {
                    let mut h = Hmac::<Sha256>::new_from_slice(black_box(&seed)).unwrap();
                    h.update(black_box(&data));
                    h.finalize().into_bytes().to_vec()
                },
                "hkdf-sha256-extract-expand32" => {
                    let hk = hkdf::Hkdf::<Sha256>::new(Some(black_box(&seed)), black_box(&data));
                    let mut output = [0u8; 32];
                    hk.expand(black_box(b"public benchmark info"), &mut output).unwrap();
                    output.to_vec()
                },
                _ => signing.try_sign(black_box(&data)).unwrap().to_bytes().to_vec(),
            }};
            for _ in 0..100 { black_box(execute()); }
            let expected = execute();
            let started = Instant::now();
            for _ in 0..iterations { black_box(execute()); }
            let elapsed = started.elapsed().as_nanos();
            println!("{{\\"operation\\":\\"{}\\",\\"input_bytes\\":{},\\"iterations\\":{},\\"elapsed_ns\\":{},\\"ns_per_op\\":{},\\"public_output_hex\\":\\"{}\\"}}",operation,length,iterations,elapsed,elapsed as f64/iterations as f64,hex(&expected));
        }
    }
}
'''
common='''[package]
name = "spiral-secret-copy-benchmark"
version = "0.0.0"
edition = "2021"
publish = false
[dependencies]
sha2 = { version = "=0.11.1", features = ["zeroize"] }
hmac = { version = "=0.13.0", features = ["zeroize"] }
hkdf = HKDF
ed25519-dalek = { version = "=3.0.0", features = ["zeroize"] }
zeroize = "=1.9.1"
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
panic = "unwind"
'''
for variant in ['baseline','candidate']:
    directory=root/variant;(directory/'src').mkdir(parents=True,exist_ok=True)
    (directory/'src/main.rs').write_text(source)
    manifest=common.replace('hkdf = HKDF','hkdf = "=0.13.0"' if variant=='baseline' else 'hkdf = { version = "=0.13.0", features = ["zeroize"] }')
    if variant=='candidate':
        manifest+='\n[patch.crates-io]\n'
        for name in ['digest','hmac','hkdf','ed25519-dalek','curve25519-dalek']:
            manifest+=f'{name} = {{ path = "{repo}/third_party/rustcrypto/{name}" }}\n'
    (directory/'Cargo.toml').write_text(manifest)
manifest={}
for name in ['digest','hmac','hkdf','ed25519-dalek','curve25519-dalek']:
    base=repo/'third_party/rustcrypto'/name
    for p in sorted(base.rglob('*')):
        if p.is_file() and (p.suffix=='.rs' or p.name=='Cargo.toml'):
            manifest[str(p.relative_to(repo))]=hashlib.sha256(p.read_bytes()).hexdigest()
(root/'candidate-source-before.json').write_text(json.dumps(manifest,indent=2)+'\n')
