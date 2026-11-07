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

pub mod admission;
mod buffer;
pub mod channel;
pub mod error;
mod ffi;
pub mod handshake;
pub mod identity;
pub mod records;
mod schedule;
pub mod secret;
#[cfg(feature = "parser-fuzz")]
#[doc(hidden)]
pub mod test_support;
pub mod transport;
pub mod wire;
pub mod worker;
pub use error::{Error, Result};
