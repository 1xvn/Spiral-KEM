//! Ring-only public known-answer control. No TLS, Spiral, worker, or secret key.
#![forbid(unsafe_code)]
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "aes256".into());
    let algorithm = match mode.as_str() {
        "aes128" => &aead::AES_128_GCM,
        "aes256" => &aead::AES_256_GCM,
        "chacha" => &aead::CHACHA20_POLY1305,
        _ => panic!("aes128 | aes256 | chacha"),
    };
    // Fixed public fixtures; never linked into the lab's production API.
    let key = LessSafeKey::new(UnboundKey::new(algorithm, &vec![7; algorithm.key_len()]).unwrap());
    let mut digest = Sha256::new();
    let mut case = 0u32;
    let lengths = (0..=33).chain([
        63, 64, 65, 119, 120, 121, 127, 128, 129, 255, 256, 257, 16383, 16384, 16401,
    ]);
    for length in lengths {
        for aad_len in [0, 5, 13, 32] {
            let aad = vec![0x55; aad_len];
            let original: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            let mut nonce = [0; 12];
            nonce[8..].copy_from_slice(&case.to_be_bytes());
            let mut appended = original.clone();
            key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut appended,
            )
            .unwrap();
            let mut separated = original.clone();
            let tag = key
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    &mut separated,
                )
                .unwrap();
            separated.extend_from_slice(tag.as_ref());
            assert_eq!(appended, separated);
            digest.update(case.to_be_bytes());
            digest.update(&appended);
            let opened = key
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    &mut appended,
                )
                .unwrap();
            assert_eq!(opened, original);
            case += 1;
        }
    }
    println!(
        "{}",
        serde_json::json!({"algorithm":mode,"cases":case,"ciphertext_sha256":hex::encode(digest.finalize()),"roundtrip_and_append_vs_separate":true})
    );
}
