//! Public fixtures and raw secret-flow observations of production record opening.
//!
//! The ignored traces intentionally preserve authentication-decision taint and
//! every Memcheck diagnostic. They do not declassify keys, tags, plaintext or
//! Result values, and a completed trace is not a constant-time approval.

use crate::{
    buffer::{Buffer, Pool},
    records::{Rx, Tx},
    secret::{Plaintext, Secret},
    wire::{Header, CLOSE, DATA, HEADER},
    Error,
};
use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use std::sync::Arc;

const LENGTHS: [usize; 7] = [1, 16, 63, 64, 65, 1024, 16384];
const PREFIX: [u8; 4] = [0x31, 0x32, 0x33, 0x34];
const SID: [u8; 16] = [0x29; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    DataValid,
    DataBadTag,
    DataBadHeader,
    CloseValid,
    CloseInvalidReason,
}

impl Mode {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn parse(value: &str) -> Self {
        match value {
            "data-valid" => Self::DataValid,
            "data-bad-tag" => Self::DataBadTag,
            "data-bad-header" => Self::DataBadHeader,
            "close-valid" => Self::CloseValid,
            "close-invalid-reason" => Self::CloseInvalidReason,
            _ => panic!("unknown public receive trace mode"),
        }
    }

    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn label(self) -> &'static str {
        match self {
            Self::DataValid => "data-valid",
            Self::DataBadTag => "data-bad-tag",
            Self::DataBadHeader => "data-bad-header",
            Self::CloseValid => "close-valid",
            Self::CloseInvalidReason => "close-invalid-reason",
        }
    }
}

#[derive(Clone, Copy)]
struct Parameters {
    mode: Mode,
    role: u8,
    length: usize,
    reason: u8,
    tag_index: u8,
}

impl Parameters {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn from_environment() -> Self {
        fn number(name: &str, fallback: &str) -> usize {
            std::env::var(name)
                .unwrap_or_else(|_| fallback.to_owned())
                .parse()
                .expect("invalid public receive trace number")
        }
        let mode = Mode::parse(
            &std::env::var("SPIRAL_RX_TRACE_MODE").expect("SPIRAL_RX_TRACE_MODE is required"),
        );
        let role = number("SPIRAL_RX_TRACE_ROLE", "0");
        let length = number(
            "SPIRAL_RX_TRACE_LENGTH",
            if matches!(
                mode,
                Mode::DataValid | Mode::DataBadTag | Mode::DataBadHeader
            ) {
                "64"
            } else {
                "1"
            },
        );
        let reason = number(
            "SPIRAL_RX_TRACE_REASON",
            if mode == Mode::CloseInvalidReason {
                "3"
            } else {
                "0"
            },
        );
        assert!(role <= 1, "public role must be zero or one");
        if matches!(
            mode,
            Mode::DataValid | Mode::DataBadTag | Mode::DataBadHeader
        ) {
            assert!(LENGTHS.contains(&length));
        } else {
            assert_eq!(length, 1);
        }
        if mode == Mode::CloseInvalidReason {
            assert!(reason == 3 || reason == 255);
        } else {
            assert_eq!(reason, 0);
        }
        let tag_index = number("SPIRAL_RX_TRACE_TAG_INDEX", "15");
        assert!(tag_index < 16);
        Self {
            mode,
            role: role as u8,
            length,
            reason: reason as u8,
            tag_index: tag_index as u8,
        }
    }
}

fn public_key_bytes() -> [u8; 32] {
    core::array::from_fn(|index| (index as u8) ^ 0xa7)
}

fn fresh_key() -> Secret<32> {
    let mut key = Secret::zeros();
    key.bytes_mut().copy_from_slice(&public_key_bytes());
    key
}

fn public_plaintext(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(13).wrapping_add(7))
        .collect()
}

fn buffer(pool: &Arc<Pool>, raw: &[u8]) -> Buffer {
    let mut buffer = pool.take().unwrap();
    buffer.data.extend_from_slice(raw);
    buffer
}

/// Construct defined, public test packets before a fresh receive key is tainted.
fn fixture(parameters: Parameters) -> Vec<u8> {
    let mut sender = Tx::new(fresh_key(), PREFIX, SID, parameters.role).unwrap();
    match parameters.mode {
        Mode::DataValid | Mode::DataBadTag | Mode::DataBadHeader => {
            let plaintext = public_plaintext(parameters.length);
            let pool = Pool::new();
            let mut raw = sender
                .data(Plaintext {
                    buffer: buffer(&pool, &plaintext),
                    start: 0,
                    length: plaintext.len(),
                })
                .unwrap()
                .as_ref()
                .to_vec();
            if parameters.mode == Mode::DataBadTag {
                let at = raw.len() - 16 + parameters.tag_index as usize;
                raw[at] ^= 1;
            }
            if parameters.mode == Mode::DataBadHeader {
                raw[6] = 0xff;
            }
            raw
        }
        Mode::CloseValid => sender.close(0).unwrap().to_vec(),
        Mode::CloseInvalidReason => {
            // Tx::close correctly rejects these reasons. Independently seal a
            // syntax-valid packet so Rx reaches the post-authentication check.
            let header = Header {
                kind: CLOSE,
                role: parameters.role,
                sid: SID,
                sequence: 0,
                length: 17,
            }
            .encode()
            .unwrap();
            let mut raw = header.to_vec();
            raw.push(parameters.reason);
            let mut nonce = [0; 12];
            nonce[..4].copy_from_slice(&PREFIX);
            let cipher = ChaCha20Poly1305::new_from_slice(&public_key_bytes()).unwrap();
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), &header, &mut raw[HEADER..])
                .unwrap();
            raw.extend_from_slice(&tag);
            raw
        }
    }
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
use crate::valgrind_audit::{require_valgrind, mark_secret};

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "positive control: must report a secret-dependent conditional branch"]
fn positive_secret_branch() {
    require_valgrind();
    let mut bit = [1u8];
    mark_secret(&mut bit);
    if std::hint::black_box(bit[0]) != 0 {
        std::hint::black_box(17usize);
    }
    println!("RX_AUDIT_POSITIVE_COMPLETED branch");
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "positive control: must report a secret-dependent memory address"]
fn positive_secret_address() {
    require_valgrind();
    let table = std::hint::black_box([0x31u8, 0x47u8]);
    let mut index = [1u8];
    mark_secret(&mut index);
    // SAFETY: this fixture's actual index is exactly one, inside a two-byte
    // live table. Marking it secret only changes Memcheck shadow state.
    // The volatile access prevents replacing the intended lookup with a value.
    let value = unsafe { std::ptr::read_volatile(table.as_ptr().add(index[0] as usize)) };
    std::hint::black_box(value);
    println!("RX_AUDIT_POSITIVE_COMPLETED address");
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
#[test]
#[ignore = "raw key/prefix taint trace; authentication and cleanup warnings remain"]
fn trace_actual_receive() {
    require_valgrind();
    let parameters = Parameters::from_environment();
    let raw = fixture(parameters);
    let pool = Pool::new();
    let input = buffer(&pool, &raw);
    let mut key = fresh_key();
    let mut prefix = PREFIX;
    let taint = std::env::var("SPIRAL_RX_TRACE_TAINT").unwrap_or_else(|_| "secret".into());
    assert!(taint == "secret" || taint == "public");
    if taint == "secret" {
        mark_secret(key.bytes_mut());
        mark_secret(&mut prefix);
    }
    let mut receiver = Rx::new(key, prefix, SID, 1 - parameters.role).unwrap();
    let result = receiver.decode(input);
    // Retain the actual production call and its output without branching on or
    // serializing secret-derived contents in this trace harness. Result drop
    // and production authentication decisions remain visible to Memcheck.
    std::hint::black_box(&result);
    drop(result);
    drop(receiver);
    println!(
        "RX_AUDIT_COMPLETED {} role={} length={} reason={} tag_index={} taint={}",
        parameters.mode.label(),
        parameters.role,
        parameters.length,
        parameters.reason,
        parameters.tag_index,
        taint
    );
}

fn check_public_fixture(parameters: Parameters) {
    let raw = fixture(parameters);
    let pool = Pool::new();
    let mut receiver = Rx::new(fresh_key(), PREFIX, SID, 1 - parameters.role).unwrap();
    match parameters.mode {
        Mode::DataValid => {
            let (kind, plaintext) = receiver.decode(buffer(&pool, &raw)).unwrap();
            assert_eq!(kind, DATA);
            assert_eq!(plaintext.as_bytes(), public_plaintext(parameters.length));
            drop(plaintext);
            assert_eq!(receiver.expected_sequence(), 1);
            assert!(!receiver.closed);
            assert!(matches!(
                receiver.decode(buffer(&pool, &raw)),
                Err(Error::Input)
            ));
            assert!(receiver.closed);
            assert_eq!(receiver.expected_sequence(), 1);
        }
        Mode::CloseValid => {
            let (kind, plaintext) = receiver.decode(buffer(&pool, &raw)).unwrap();
            assert_eq!(kind, CLOSE);
            assert_eq!(plaintext.as_bytes(), &[0]);
            drop(plaintext);
            assert!(receiver.closed);
            assert_eq!(receiver.expected_sequence(), 1);
            assert!(matches!(
                receiver.decode(buffer(&pool, &raw)),
                Err(Error::Closed)
            ));
        }
        Mode::DataBadTag | Mode::DataBadHeader | Mode::CloseInvalidReason => {
            let expected_error = if parameters.mode == Mode::DataBadTag {
                Error::Authentication
            } else {
                Error::Input
            };
            assert!(matches!(
                receiver.decode(buffer(&pool, &raw)),
                Err(error) if error == expected_error
            ));
            assert!(receiver.closed);
            assert_eq!(receiver.expected_sequence(), 0);
            let valid = fixture(Parameters {
                mode: if matches!(parameters.mode, Mode::DataBadTag | Mode::DataBadHeader) {
                    Mode::DataValid
                } else {
                    Mode::CloseValid
                },
                reason: 0,
                ..parameters
            });
            assert!(matches!(
                receiver.decode(buffer(&pool, &valid)),
                Err(Error::Closed)
            ));
        }
    }
}

#[test]
fn public_fixture_contract() {
    let mut checked = 0;
    for role in 0..2 {
        for length in LENGTHS {
            for mode in [Mode::DataValid, Mode::DataBadTag, Mode::DataBadHeader] {
                check_public_fixture(Parameters {
                    mode,
                    role,
                    length,
                    reason: 0,
                    tag_index: 15,
                });
                checked += 1;
            }
        }
        for tag_index in 0..15 {
            check_public_fixture(Parameters {
                mode: Mode::DataBadTag,
                role,
                length: 65,
                reason: 0,
                tag_index,
            });
            checked += 1;
        }
        check_public_fixture(Parameters {
            mode: Mode::CloseValid,
            role,
            length: 1,
            reason: 0,
            tag_index: 15,
        });
        checked += 1;
        for reason in [3, 255] {
            check_public_fixture(Parameters {
                mode: Mode::CloseInvalidReason,
                role,
                length: 1,
                reason,
                tag_index: 15,
            });
            checked += 1;
        }
    }
    assert_eq!(checked, 78);
    println!(
        "RX_FUNCTIONAL_CASE {}",
        serde_json::json!({
            "id": "public_fixture_contract", "status": "passed", "fixtures_checked": checked,
            "scope": "defined public fixtures; separate from raw key-taint traces"
        })
    );
}

#[test]
fn poly1305_state_requires_drop() {
    assert!(
        std::mem::needs_drop::<poly1305::Poly1305>(),
        "pinned Poly1305 zeroize feature must keep state cleanup enabled"
    );
}
