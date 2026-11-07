//! Public hash/HKDF/Ed25519 fixtures, independent of TLS and Spiral.
#![forbid(unsafe_code)]
use ring::{
    digest, hkdf,
    signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519},
};
use sha2::{Digest, Sha256};
struct Length(usize);
impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}
fn main() {
    let signing = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let mut aggregate = Sha256::new();
    let mut case = 0u32;
    for (hash, kdf) in [
        (&digest::SHA256, hkdf::HKDF_SHA256),
        (&digest::SHA384, hkdf::HKDF_SHA384),
        (&digest::SHA512, hkdf::HKDF_SHA512),
    ] {
        for length in (0..=260).chain([511, 512, 513, 1024, 4096]) {
            let message: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            let expected = digest::digest(hash, &message);
            for chunk in [1, 7, 63, 64, 127] {
                let mut context = digest::Context::new(hash);
                for bytes in message.chunks(chunk) {
                    context.update(bytes);
                }
                assert_eq!(context.finish().as_ref(), expected.as_ref());
            }
            let prk = hkdf::Salt::new(kdf, &[0x55; 37]).extract(&message);
            let case_bytes = case.to_be_bytes();
            let info: [&[u8]; 2] = [b"control", &case_bytes];
            let mut key = [0; 32];
            prk.expand(&info, Length(32))
                .unwrap()
                .fill(&mut key)
                .unwrap();
            let sig = signing.sign(&message);
            UnparsedPublicKey::new(&ED25519, signing.public_key().as_ref())
                .verify(&message, sig.as_ref())
                .unwrap();
            aggregate.update(case_bytes);
            aggregate.update(expected.as_ref());
            aggregate.update(key);
            aggregate.update(sig.as_ref());
            case += 1;
        }
    }
    println!(
        "{}",
        serde_json::json!({"cases":case,"sha256":hex::encode(aggregate.finalize()),"algorithms":"SHA256/SHA384/SHA512, HKDF, Ed25519, five streaming chunk sizes"})
    );
}
