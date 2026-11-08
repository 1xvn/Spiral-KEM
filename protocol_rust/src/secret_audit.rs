//! Test-only observations of live pooled allocations after production cleanup.
//!
//! Each fixture initializes every byte of capacity before truncation. The only
//! unsafe read is of that same initialized allocation after it is returned by
//! the pool; no freed address is read and no resize masks a failed wipe.

use crate::{
    buffer::{Buffer, Pool},
    records::{Rx, Tx},
    secret::{Plaintext, Secret},
    wire::{self, Header, CLOSE, DATA, HEADER},
    Error,
};
use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use std::sync::Arc;

const LENGTHS: [usize; 7] = [1, 16, 63, 64, 65, 1024, 16384];
const PREFIX: [u8; 4] = [0x71, 0x72, 0x73, 0x74];
const SID: [u8; 16] = [0x47; 16];

fn public_key_bytes() -> [u8; 32] {
    core::array::from_fn(|index| 0x31 + index as u8)
}

fn key() -> Secret<32> {
    let mut key = Secret::zeros();
    key.bytes_mut().copy_from_slice(&public_key_bytes());
    key
}

fn sender(role: u8) -> Tx {
    Tx::new(key(), PREFIX, SID, role).unwrap()
}

fn receiver(sender_role: u8) -> Rx {
    Rx::new(key(), PREFIX, SID, 1 - sender_role).unwrap()
}

fn data_frame(sender: &mut Tx, value: &[u8]) -> Vec<u8> {
    // Keep sender buffers in their own pool so receive-pool reuse is unambiguous.
    let pool = Pool::new();
    let mut buffer = pool.take().unwrap();
    buffer.data.extend_from_slice(value);
    sender
        .data(Plaintext {
            buffer,
            start: 0,
            length: value.len(),
        })
        .unwrap()
        .as_ref()
        .to_vec()
}

struct Allocation {
    pointer: *const u8,
    capacity: usize,
}

fn receive_fixture(pool: &Arc<Pool>, raw: &[u8]) -> (Buffer, Allocation) {
    let mut buffer = pool.take().unwrap();
    let capacity = buffer.data.capacity();
    assert!(raw.len() <= capacity);
    // Initialize the full allocation, including the later truncated tail. Thus
    // a buggy cleanup that omits spare capacity leaves observable 0xa5 bytes.
    buffer.data.resize(capacity, 0xa5);
    buffer.data[..raw.len()].copy_from_slice(raw);
    buffer.data.truncate(raw.len());
    let allocation = Allocation {
        pointer: buffer.data.as_ptr(),
        capacity,
    };
    (buffer, allocation)
}

fn assert_reused_allocation_is_zero(pool: &Arc<Pool>, expected: Allocation) {
    let buffer = pool.take().unwrap();
    assert_eq!(
        buffer.data.len(),
        0,
        "returned plaintext length survived cleanup"
    );
    assert_eq!(
        buffer.data.capacity(),
        expected.capacity,
        "pool allocation changed"
    );
    assert_eq!(
        buffer.data.as_ptr(),
        expected.pointer,
        "pool did not return the observed allocation"
    );
    // SAFETY: receive_fixture initialized every byte of this allocation before
    // truncation. Production Buffer::drop retains it in the pool, and the
    // pointer/capacity checks above establish reuse. `buffer` still uniquely
    // owns the live allocation for the duration of this read. No freed memory,
    // uninitialized spare bytes, or mutable aliases are inspected.
    let allocation =
        unsafe { std::slice::from_raw_parts(buffer.data.as_ptr(), buffer.data.capacity()) };
    assert!(
        allocation.iter().all(|byte| *byte == 0),
        "production cleanup left nonzero bytes in the reused allocation"
    );
    // Do not resize before the observation: resize would itself fill the tail.
    drop(buffer);
}

fn emit(id: &str, buffers_checked: usize) {
    println!(
        "SECRET_AUDIT_CASE {}",
        serde_json::json!({
            "id": id, "status": "passed", "buffers_checked": buffers_checked,
            "scope": "initialized live pooled allocation; no key/register-copy claim"
        })
    );
}

#[test]
fn valid_data_and_following_close_wipe_full_capacity_before_reuse() {
    let mut checked = 0;
    for role in 0..2 {
        for (index, length) in LENGTHS.into_iter().enumerate() {
            let pool = Pool::new();
            let mut tx = sender(role);
            let mut rx = receiver(role);
            let expected: Vec<u8> = (0..length).map(|i| (i as u8).wrapping_mul(13)).collect();
            let raw = data_frame(&mut tx, &expected);
            let (buffer, allocation) = receive_fixture(&pool, &raw);
            let (kind, plaintext) = rx.decode(buffer).unwrap();
            assert_eq!(kind, DATA);
            assert!(
                plaintext.as_bytes() == expected,
                "valid DATA plaintext changed"
            );
            drop(plaintext);
            assert_reused_allocation_is_zero(&pool, allocation);
            checked += 1;

            let reason = (index % 3) as u8;
            let close = tx.close(reason).unwrap();
            let (buffer, allocation) = receive_fixture(&pool, &close);
            let (kind, plaintext) = rx.decode(buffer).unwrap();
            assert_eq!(kind, CLOSE);
            assert!(
                plaintext.as_bytes() == [reason],
                "valid CLOSE plaintext changed"
            );
            drop(plaintext);
            assert!(rx.closed);
            assert_reused_allocation_is_zero(&pool, allocation);
            checked += 1;
        }
    }
    assert_eq!(checked, 28);
    emit(
        "valid_data_and_following_close_wipe_full_capacity_before_reuse",
        checked,
    );
}

#[test]
fn valid_close_and_post_close_rejection_wipe_full_capacity_before_reuse() {
    let mut checked = 0;
    for role in 0..2 {
        for reason in 0..3 {
            let pool = Pool::new();
            let close = sender(role).close(reason).unwrap();
            let mut rx = receiver(role);
            let (buffer, allocation) = receive_fixture(&pool, &close);
            let (kind, plaintext) = rx.decode(buffer).unwrap();
            assert_eq!(kind, CLOSE);
            assert!(plaintext.as_bytes() == [reason]);
            drop(plaintext);
            assert_reused_allocation_is_zero(&pool, allocation);
            checked += 1;

            let (buffer, allocation) = receive_fixture(&pool, &close);
            assert!(matches!(rx.decode(buffer), Err(Error::Closed)));
            assert_reused_allocation_is_zero(&pool, allocation);
            checked += 1;
        }
    }
    assert_eq!(checked, 12);
    emit(
        "valid_close_and_post_close_rejection_wipe_full_capacity_before_reuse",
        checked,
    );
}

#[test]
fn authentication_and_syntax_failures_wipe_full_capacity_and_remain_poisoned() {
    let mut checked = 0;
    for role in 0..2 {
        for length in LENGTHS {
            let pool = Pool::new();
            let valid = data_frame(&mut sender(role), &vec![0x93; length]);
            let mut bad_tag = valid.clone();
            *bad_tag.last_mut().unwrap() ^= 1;
            let mut bad_header = valid.clone();
            bad_header[6] = 0xff;
            let malformed = [
                (bad_tag, Error::Authentication),
                (bad_header, Error::Input),
                (Vec::new(), Error::Input),
                (valid[..HEADER - 1].to_vec(), Error::Input),
                (valid[..HEADER].to_vec(), Error::Input),
                (valid[..valid.len() - 1].to_vec(), Error::Input),
            ];
            for (raw, expected_error) in malformed {
                let mut rx = receiver(role);
                let (buffer, allocation) = receive_fixture(&pool, &raw);
                assert!(matches!(rx.decode(buffer), Err(error) if error == expected_error));
                assert!(rx.closed);
                assert_reused_allocation_is_zero(&pool, allocation);
                checked += 1;

                let (buffer, allocation) = receive_fixture(&pool, &valid);
                assert!(matches!(rx.decode(buffer), Err(Error::Closed)));
                assert_reused_allocation_is_zero(&pool, allocation);
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 168);
    emit(
        "authentication_and_syntax_failures_wipe_full_capacity_and_remain_poisoned",
        checked,
    );
}

fn authenticated_invalid_close(role: u8, reason: u8) -> Vec<u8> {
    let head = Header {
        kind: CLOSE,
        role,
        sid: SID,
        sequence: 0,
        length: 17,
    }
    .encode()
    .unwrap();
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&PREFIX);
    let cipher = ChaCha20Poly1305::new_from_slice(&public_key_bytes()).unwrap();
    let mut plaintext = [reason];
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &head, &mut plaintext)
        .unwrap();
    let mut raw = head.to_vec();
    raw.extend(plaintext);
    raw.extend_from_slice(&tag);
    assert!(wire::parse(&raw).is_ok());
    raw
}

#[test]
fn authenticated_invalid_close_reason_wipes_decrypted_bytes_and_poisoned_retry() {
    let mut checked = 0;
    for role in 0..2 {
        for reason in [3, 255] {
            let pool = Pool::new();
            let malformed = authenticated_invalid_close(role, reason);
            let valid = sender(role).close(0).unwrap();
            let mut rx = receiver(role);
            let (buffer, allocation) = receive_fixture(&pool, &malformed);
            assert!(matches!(rx.decode(buffer), Err(Error::Input)));
            assert!(rx.closed);
            assert_reused_allocation_is_zero(&pool, allocation);
            checked += 1;

            let (buffer, allocation) = receive_fixture(&pool, &valid);
            assert!(matches!(rx.decode(buffer), Err(Error::Closed)));
            assert_reused_allocation_is_zero(&pool, allocation);
            checked += 1;
        }
    }
    assert_eq!(checked, 8);
    emit(
        "authenticated_invalid_close_reason_wipes_decrypted_bytes_and_poisoned_retry",
        checked,
    );
}
