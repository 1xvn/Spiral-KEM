//! Opt-in adapters for fixed PUBLIC synthetic record fixtures only.
//!
//! This module cannot construct a Session or Established value, accepts no key
//! material, and only initializes counters once, before the first operation.
#![forbid(unsafe_code)]

use super::{Rx, Tx};
use crate::{
    buffer::Pool,
    secret::{Plaintext, Secret},
    Error, Result,
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub sequence: u64,
    pub bytes: u64,
    pub closed: bool,
    pub key_live: bool,
}

pub struct RecordPair {
    tx: Tx,
    rx: Rx,
    pool: Arc<Pool>,
}

fn public_key() -> Secret<32> {
    let mut key = Secret::zeros();
    for (index, byte) in key.bytes_mut().iter_mut().enumerate() {
        *byte = index as u8;
    }
    key
}

impl RecordPair {
    /// Fixed synthetic starting states. Scenario 3 is an exhausted open state
    /// used only to test a guard; it is not a normally reachable session.
    pub fn new(scenario: u8, sender_role: u8) -> Result<Self> {
        const PRESETS: [(u64, u64); 7] = [
            (0, 0),
            ((1 << 20) - 2, 0),
            ((1 << 20) - 1, 0),
            (1 << 20, 0),
            (0, (1 << 30) - 2),
            (0, (1 << 30) - 1),
            (0, (1 << 30) - 1 - 16383),
        ];
        let &(sequence, bytes) = PRESETS.get(scenario as usize).ok_or(Error::Input)?;
        if sender_role > 1 {
            return Err(Error::Input);
        }
        let sid = core::array::from_fn(|index| 0x10 + index as u8);
        let mut tx = Tx::new(public_key(), [0xa0, 0xa1, 0xa2, 0xa3], sid, sender_role)?;
        let mut rx = Rx::new(public_key(), [0xa0, 0xa1, 0xa2, 0xa3], sid, 1 - sender_role)?;
        tx.seq = sequence;
        tx.bytes = bytes;
        rx.seq = sequence;
        rx.bytes = bytes;
        Ok(Self {
            tx,
            rx,
            pool: Pool::new(),
        })
    }

    pub fn snapshots(&self) -> (Snapshot, Snapshot) {
        (
            Snapshot {
                sequence: self.tx.seq,
                bytes: self.tx.bytes,
                closed: self.tx.closed,
                key_live: self.tx.key.is_some(),
            },
            Snapshot {
                sequence: self.rx.seq,
                bytes: self.rx.bytes,
                closed: self.rx.closed,
                key_live: self.rx.key.is_some(),
            },
        )
    }

    #[inline(never)]
    pub fn data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = self.pool.take()?;
        buffer.data.extend_from_slice(plaintext);
        let result = self.tx.data(Plaintext {
            buffer,
            start: 0,
            length: plaintext.len(),
        })?;
        Ok(result.as_ref().to_vec())
    }

    #[inline(never)]
    pub fn close(&mut self, reason: u8) -> Result<Vec<u8>> {
        self.tx.close(reason).map(|wire| wire.to_vec())
    }

    #[inline(never)]
    pub fn decode(&mut self, raw: &[u8]) -> Result<(u8, Vec<u8>)> {
        let mut buffer = self.pool.take()?;
        buffer.data.extend_from_slice(raw);
        let (kind, plaintext) = self.rx.decode(buffer)?;
        Ok((kind, plaintext.as_bytes().to_vec()))
    }
}
