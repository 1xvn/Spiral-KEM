//! Feature-off public API compatibility, separate from feature-on wipe witnesses.
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha512};

#[test]
fn public_signing_and_scalar_reduction_keep_rfc8032_outputs_without_cleanup() {
    let seed: [u8; 32] = hex::decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ).unwrap().try_into().unwrap();
    let expected = hex::decode(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )).unwrap();
    let key = SigningKey::from_bytes(&seed);
    let signature: Signature = key.try_sign(b"").unwrap();
    assert_eq!(signature.to_bytes().as_slice(), expected);
    assert!(key.verifying_key().verify_strict(b"", &signature).is_ok());
    assert!(key.verifying_key().verify_strict(b"changed", &signature).is_err());
    let mut noncanonical = signature.to_bytes();
    noncanonical[32..].fill(0xff);
    assert!(key.verifying_key().verify_strict(b"", &Signature::from_bytes(&noncanonical)).is_err());

    let seed: [u8; 32] = hex::decode(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    ).unwrap().try_into().unwrap();
    let expected = hex::decode(concat!(
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41",
        "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
    )).unwrap();
    let key = SigningKey::from_bytes(&seed);
    let hash = Sha512::new().chain_update(b"abc");
    let signature = key.sign_prehashed(hash.clone(), None).unwrap();
    assert_eq!(signature.to_bytes().as_slice(), expected);
    assert!(key.verifying_key().verify_prehashed_strict(hash, None, &signature).is_ok());
}
