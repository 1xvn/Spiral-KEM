use std::{hint::black_box, time::Instant};
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
            let execute = || -> [u8; 64] { match operation {
                "hmac-sha256" => {
                    let mut h = Hmac::<Sha256>::new_from_slice(black_box(&seed)).unwrap();
                    h.update(black_box(&data));
                    { let mut output = [0u8; 64]; output[..32].copy_from_slice(&h.finalize().into_bytes()); output }
                },
                "hkdf-sha256-extract-expand32" => {
                    let hk = hkdf::Hkdf::<Sha256>::new(Some(black_box(&seed)), black_box(&data));
                    let mut output = [0u8; 64];
                    hk.expand(black_box(b"public benchmark info"), &mut output[..32]).unwrap();
                    output
                },
                _ => signing.try_sign(black_box(&data)).unwrap().to_bytes(),
            }};
            for _ in 0..100 { black_box(execute()); }
            let expected = execute();
            let started = Instant::now();
            for _ in 0..iterations { black_box(execute()); }
            let elapsed = started.elapsed().as_nanos();
            println!("{{\"operation\":\"{}\",\"input_bytes\":{},\"iterations\":{},\"elapsed_ns\":{},\"ns_per_op\":{},\"public_output_hex\":\"{}\"}}",operation,length,iterations,elapsed,elapsed as f64/iterations as f64,hex(&expected[..if operation == "ed25519-sign" {64} else {32}]));
        }
    }
}
