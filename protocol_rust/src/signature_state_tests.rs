//! Independent public-fixture regression for the owned Ed25519 capability.

use crate::{identity::ServerIdentity, Error};
use ed25519_dalek::{Signature, VerifyingKey};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

#[test]
fn owned_ed25519_matches_ring_at_hash_boundaries_and_rejects_mutation() {
    let seeds = [
        [0u8; 32],
        [0xffu8; 32],
        core::array::from_fn(|index| index as u8),
        core::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(7)),
    ];
    let lengths = [0, 1, 63, 64, 65, 127, 128, 129, 1024, 16384];
    let mut pairs = 0;
    let mut changed_messages = 0;
    let mut changed_signature_bytes = 0;

    for (seed_index, seed) in seeds.iter().enumerate() {
        for length in lengths {
            // These fixed fixtures are public test data, never operational keys.
            let message: Vec<u8> = (0..length)
                .map(|index| (index as u8).wrapping_mul(17).wrapping_add(0xa5))
                .collect();
            let owner = ServerIdentity::fixture(seed);
            let independent = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
            let public = owner.public_key();
            assert_eq!(public.as_slice(), independent.public_key().as_ref());

            let signature = owner.sign(&message).unwrap();
            let independent_signature = independent.sign(&message);
            assert_eq!(signature.to_bytes().as_slice(), independent_signature.as_ref());

            let dalek_public = VerifyingKey::from_bytes(&public).unwrap();
            let ring_public = UnparsedPublicKey::new(&ED25519, &public);
            dalek_public.verify_strict(&message, &signature).unwrap();
            dalek_public
                .verify_strict(
                    &message,
                    &Signature::from_slice(independent_signature.as_ref()).unwrap(),
                )
                .unwrap();
            ring_public.verify(&message, &signature.to_bytes()).unwrap();
            ring_public
                .verify(&message, independent_signature.as_ref())
                .unwrap();
            pairs += 1;

            let mut changed_message = message.clone();
            if let Some(first) = changed_message.first_mut() {
                *first ^= 0x80;
            } else {
                changed_message.push(0x80);
            }
            assert!(dalek_public
                .verify_strict(&changed_message, &signature)
                .is_err());
            assert!(ring_public
                .verify(&changed_message, &signature.to_bytes())
                .is_err());
            changed_messages += 1;

            if seed_index == 0 && length == 65 {
                let original = signature.to_bytes();
                for index in 0..original.len() {
                    let mut changed_signature = original;
                    changed_signature[index] ^= 1;
                    assert!(dalek_public
                        .verify_strict(
                            &message,
                            &Signature::from_slice(&changed_signature).unwrap(),
                        )
                        .is_err());
                    assert!(ring_public.verify(&message, &changed_signature).is_err());
                    changed_signature_bytes += 1;
                }
            }

            owner.close().unwrap();
            assert!(owner.is_closed().unwrap());
            assert!(matches!(owner.sign(&message), Err(Error::Closed)));
        }
    }

    assert_eq!(pairs, 40);
    assert_eq!(changed_messages, 40);
    assert_eq!(changed_signature_bytes, 64);
    println!(
        "SIGNATURE_STATE_CASE {{\"pairs_checked\":40,\"changed_messages_rejected\":40,\"changed_signature_bytes_rejected\":64,\"scope\":\"public fixtures; ring differential and revocation; no complete-wipe claim\",\"status\":\"passed\"}}"
    );
}
