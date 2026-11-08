//! Experimental v0.1-compatible transport. No production security claim.
//!
//! A session can only be opened through the authenticated Established value.
//! ```compile_fail
//! use spiral_protocol::channel::Session;
//! let _ = Session::start; // Private: arbitrary key material is not an entry point.
//! ```
#![cfg_attr(
    not(feature = "parser-fuzz"),
    doc = r#"
The parser fuzzing helper is unavailable without the `parser-fuzz` feature.
```compile_fail,E0432
use spiral_protocol::test_support;
```
"#
)]
#![cfg_attr(
    not(feature = "record-fuzz"),
    doc = r#"
The fixed-public-fixture record helper is unavailable in a default build.
```compile_fail,E0432
use spiral_protocol::record_test_support;
```
"#
)]

pub mod admission;
mod buffer;
pub mod channel;
pub mod error;
mod ffi;
pub mod handshake;
pub mod identity;
pub mod records;
#[cfg(feature = "record-fuzz")]
#[doc(hidden)]
pub use records::fuzz_support as record_test_support;
#[cfg(test)]
mod receive_audit;
mod schedule;
pub mod secret;
#[cfg(test)]
mod secret_audit;
#[cfg(test)]
mod secret_state_tests;
#[cfg(test)]
mod signature_state_tests;
#[cfg(feature = "parser-fuzz")]
#[doc(hidden)]
pub mod test_support;
pub mod transport;
pub mod wire;
pub mod worker;
pub use error::{Error, Result};

#[cfg(all(test, target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod valgrind_audit;
