//! Exercise ring with the same offset-buffer trait pattern used by rustls.
//! All keys, nonces, plaintext and AAD are public diagnostic fixtures.
#![forbid(unsafe_code)]
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
struct Prefixed {
    bytes: Vec<u8>,
    offset: usize,
}
impl AsMut<[u8]> for Prefixed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.offset..]
    }
}
impl<'a> Extend<&'a u8> for Prefixed {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.bytes.extend(iter);
    }
}
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "aes256".into());
    let algorithm = match mode.as_str() {
        "aes128" => &aead::AES_128_GCM,
        "aes256" => &aead::AES_256_GCM,
        "chacha" => &aead::CHACHA20_POLY1305,
        _ => panic!("aes128 | aes256 | chacha"),
    };
    let key = LessSafeKey::new(UnboundKey::new(algorithm, &vec![7; algorithm.key_len()]).unwrap());
    let mut aggregate = Sha256::new();
    let mut case = 0u32;
    for offset in [0, 1, 5, 15, 16, 31] {
        for length in (0..=260).chain([16384]) {
            let mut nonce = [0; 12];
            nonce[8..].copy_from_slice(&case.to_be_bytes());
            let aad = [23, 3, 3, ((length + 16) >> 8) as u8, (length + 16) as u8];
            let original: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            let mut payload = Prefixed {
                bytes: Vec::with_capacity(offset + length + 16),
                offset,
            };
            payload.bytes.resize(offset, 0);
            payload.bytes.extend_from_slice(&original);
            key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut payload,
            )
            .unwrap();
            aggregate.update(case.to_be_bytes());
            aggregate.update(payload.as_mut());
            let opened = key
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    payload.as_mut(),
                )
                .unwrap();
            assert_eq!(opened, original);
            case += 1;
        }
    }
    println!(
        "{}",
        serde_json::json!({"algorithm":mode,"cases":case,"ciphertext_sha256":hex::encode(aggregate.finalize())})
    );
}
