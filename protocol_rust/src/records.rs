#![forbid(unsafe_code)]
use crate::{
    buffer::Buffer,
    secret::{Plaintext, Secret},
    wire::{self, Header, CLOSE, DATA, HEADER, MAX_DATA, MAX_RECORDS},
    Error, Result,
};
use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
const MAX_BYTES: u64 = (1 << 30) - 1;
pub(crate) struct Tx {
    key: Option<ChaCha20Poly1305>,
    prefix: [u8; 4],
    sid: [u8; 16],
    role: u8,
    seq: u64,
    bytes: u64,
    pub closed: bool,
}
pub(crate) struct Rx {
    key: Option<ChaCha20Poly1305>,
    prefix: [u8; 4],
    sid: [u8; 16],
    role: u8,
    seq: u64,
    bytes: u64,
    pub closed: bool,
}
fn nonce(prefix: [u8; 4], seq: u64) -> [u8; 12] {
    let mut n = [0; 12];
    n[..4].copy_from_slice(&prefix);
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}
impl Tx {
    pub fn new(key: Secret<32>, prefix: [u8; 4], sid: [u8; 16], role: u8) -> Result<Self> {
        if role > 1 || sid == [0; 16] {
            return Err(Error::Input);
        }
        let key = Some(ChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|_| Error::Crypto)?);
        Ok(Self {
            key,
            prefix,
            sid,
            role,
            seq: 0,
            bytes: 0,
            closed: false,
        })
    }
    pub fn data(&mut self, p: Plaintext) -> Result<Buffer> {
        if self.closed || self.key.is_none() {
            return Err(Error::Closed);
        }
        if p.length == 0 || p.length > MAX_DATA {
            self.key = None;
            return Err(Error::Input);
        }
        if self.seq >= MAX_RECORDS - 1 || self.bytes + p.length as u64 > MAX_BYTES {
            return Err(Error::Limit(2));
        }
        self.encode(DATA, p)
    }
    pub fn close(&mut self, reason: u8) -> Result<[u8; 57]> {
        if reason > 2 {
            return Err(Error::Input);
        }
        if self.closed || self.key.is_none() {
            return Err(Error::Closed);
        }
        if self.seq >= MAX_RECORDS {
            self.key = None;
            return Err(Error::Input);
        }
        let seq = self.seq;
        self.seq += 1;
        let result = (|| {
            let head = Header {
                kind: CLOSE,
                role: self.role,
                sid: self.sid,
                sequence: seq,
                length: 17,
            }
            .encode()?;
            let mut out = [0; 57];
            out[..HEADER].copy_from_slice(&head);
            out[HEADER] = reason;
            let n = nonce(self.prefix, seq);
            let tag = self
                .key
                .as_ref()
                .ok_or(Error::Closed)?
                .encrypt_in_place_detached(
                    Nonce::from_slice(&n),
                    &head,
                    &mut out[HEADER..HEADER + 1],
                )
                .map_err(|_| Error::Crypto)?;
            out[HEADER + 1..].copy_from_slice(&tag);
            Ok(out)
        })();
        self.closed = true;
        self.key = None;
        result
    }
    fn encode(&mut self, kind: u8, p: Plaintext) -> Result<Buffer> {
        if self.closed || self.key.is_none() {
            return Err(Error::Closed);
        }
        if self.seq >= MAX_RECORDS {
            self.key = None;
            return Err(Error::Input);
        }
        let sequence = self.seq;
        self.seq += 1;
        let result = (|| {
            let Plaintext {
                mut buffer,
                start,
                length,
            } = p;
            let h = Header {
                kind,
                role: self.role,
                sid: self.sid,
                sequence,
                length: length + 16,
            }
            .encode()?;
            if buffer.data.capacity() < HEADER + length + 16 {
                return Err(Error::Internal);
            }
            buffer.data.resize(HEADER + length + 16, 0);
            buffer.data.copy_within(start..start + length, HEADER);
            buffer.data[..HEADER].copy_from_slice(&h);
            let n = nonce(self.prefix, sequence);
            let tag = self
                .key
                .as_ref()
                .ok_or(Error::Closed)?
                .encrypt_in_place_detached(
                    Nonce::from_slice(&n),
                    &h,
                    &mut buffer.data[HEADER..HEADER + length],
                )
                .map_err(|_| Error::Crypto)?;
            buffer.data[HEADER + length..].copy_from_slice(&tag);
            if kind == DATA {
                self.bytes += length as u64;
            } else {
                self.closed = true;
                self.key = None;
            }
            Ok(buffer)
        })();
        if result.is_err() {
            self.key = None;
            self.closed = true;
        }
        result
    }
}
impl Rx {
    pub fn new(key: Secret<32>, prefix: [u8; 4], sid: [u8; 16], role: u8) -> Result<Self> {
        if role > 1 || sid == [0; 16] {
            return Err(Error::Input);
        }
        let key = Some(ChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|_| Error::Crypto)?);
        Ok(Self {
            key,
            prefix,
            sid,
            role,
            seq: 0,
            bytes: 0,
            closed: false,
        })
    }
    pub fn expected_sequence(&self) -> u64 {
        self.seq
    }
    pub fn decode(&mut self, mut buf: Buffer) -> Result<(u8, Plaintext)> {
        let result = (|| {
            if self.closed || self.key.is_none() {
                return Err(Error::Closed);
            }
            let (h, _) = wire::parse(&buf.data)?;
            h.expect(None, 1 - self.role, Some(self.sid), self.seq)?;
            if !matches!(h.kind, DATA | CLOSE) {
                return Err(Error::Input);
            }
            let size = h.length - 16;
            if h.kind == DATA && self.bytes + size as u64 > MAX_BYTES {
                return Err(Error::Limit(2));
            }
            let n = nonce(self.prefix, self.seq);
            let (head, body) = buf.data.split_at_mut(HEADER);
            let (message, tag) = body.split_at_mut(size);
            self.key
                .as_ref()
                .ok_or(Error::Closed)?
                .decrypt_in_place_detached(
                    Nonce::from_slice(&n),
                    head,
                    message,
                    Tag::from_slice(tag),
                )
                .map_err(|_| Error::Authentication)?;
            if h.kind == CLOSE && (size != 1 || message[0] > 2) {
                return Err(Error::Input);
            }
            self.seq += 1;
            if h.kind == DATA {
                self.bytes += size as u64;
            } else {
                self.closed = true;
                self.key = None;
            }
            Ok((
                h.kind,
                Plaintext {
                    buffer: buf,
                    start: HEADER,
                    length: size,
                },
            ))
        })();
        if result.is_err() {
            self.key = None;
            self.closed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Pool;
    fn vector() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../protocol_v01/tests/fixtures/test_vectors_v0.1.json"
        ))
        .unwrap()
    }
    fn key(v: &serde_json::Value, name: &str) -> Secret<32> {
        let mut k = Secret::zeros();
        k.bytes_mut()
            .copy_from_slice(&hex::decode(v["expected"][name].as_str().unwrap()).unwrap());
        k
    }
    fn buf(pool: &std::sync::Arc<Pool>, v: &[u8]) -> Buffer {
        let mut b = pool.take().unwrap();
        b.data.extend_from_slice(v);
        b
    }
    fn rx(v: &serde_json::Value) -> Rx {
        Rx::new(
            key(v, "client_data_key"),
            hex::decode(v["expected"]["client_nonce_prefix"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode(v["public"]["session_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            1,
        )
        .unwrap()
    }
    #[test]
    fn golden_records_and_close() {
        let v = vector();
        let pool = Pool::new();
        let mut r = rx(&v);
        for name in ["client_data", "client_close"] {
            let wire = hex::decode(v["frames"][name].as_str().unwrap()).unwrap();
            let (_, plain) = r.decode(buf(&pool, &wire)).unwrap();
            assert_eq!(
                plain.as_bytes(),
                hex::decode(v["plaintexts"][name].as_str().unwrap()).unwrap()
            );
        }
        assert!(r.closed);
    }
    #[test]
    fn every_record_bit_tamper_poisoned() {
        let v = vector();
        let pool = Pool::new();
        let raw = hex::decode(v["frames"]["client_data"].as_str().unwrap()).unwrap();
        for byte in 0..raw.len() {
            for bit in 0..8 {
                let mut changed = raw.clone();
                changed[byte] ^= 1 << bit;
                let mut r = rx(&v);
                assert!(r.decode(buf(&pool, &changed)).is_err());
                assert!(r.decode(buf(&pool, &raw)).is_err());
            }
        }
    }
    #[test]
    fn duplicate_and_out_of_order_rejected() {
        let v = vector();
        let pool = Pool::new();
        let raw = hex::decode(v["frames"]["client_data"].as_str().unwrap()).unwrap();
        let mut r = rx(&v);
        drop(r.decode(buf(&pool, &raw)).unwrap());
        assert!(r.decode(buf(&pool, &raw)).is_err());
        let close = hex::decode(v["frames"]["client_close"].as_str().unwrap()).unwrap();
        assert!(rx(&v).decode(buf(&pool, &close)).is_err());
    }
    #[test]
    fn encode_matches_fixture_and_reserves_close() {
        let v = vector();
        let pool = Pool::new();
        let mut t = Tx::new(
            key(&v, "client_data_key"),
            hex::decode(v["expected"]["client_nonce_prefix"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode(v["public"]["session_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            0,
        )
        .unwrap();
        let data = hex::decode(v["plaintexts"]["client_data"].as_str().unwrap()).unwrap();
        let p = Plaintext {
            buffer: buf(&pool, &data),
            start: 0,
            length: data.len(),
        };
        assert_eq!(
            hex::encode(t.data(p).unwrap().data.as_slice()),
            v["frames"]["client_data"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(t.close(0).unwrap()),
            v["frames"]["client_close"].as_str().unwrap()
        );
        assert!(t.close(0).is_err());
    }
    #[test]
    fn pool_capacity_is_fixed_and_allocation_is_reused() {
        let pool = Pool::new();
        let mut a = Vec::new();
        for _ in 0..18 {
            a.push(buf(&pool, b"secret material"));
        }
        assert!(pool.take().is_err());
        drop(a);
        let b = pool.take().unwrap();
        assert!(b.data.is_empty());
        assert_eq!(b.data.capacity(), 16440);
    }
    #[test]
    fn count_and_byte_limits_still_allow_close() {
        let pool = Pool::new();
        for bytes_limit in [false, true] {
            let mut t = Tx::new(Secret::zeros(), [0; 4], [1; 16], 0).unwrap();
            if bytes_limit {
                t.bytes = MAX_BYTES;
            } else {
                t.seq = MAX_RECORDS - 1;
            }
            assert!(matches!(
                t.data(Plaintext {
                    buffer: buf(&pool, b"x"),
                    start: 0,
                    length: 1
                }),
                Err(Error::Limit(2))
            ));
            let held: Vec<_> = (0..18).map(|_| pool.take().unwrap()).collect();
            assert!(pool.take().is_err());
            let close = t.close(2).unwrap();
            assert_eq!(wire::parse(&close).unwrap().0.kind, CLOSE);
            drop(held);
        }
    }
    #[tokio::test]
    async fn exhausted_buffers_wait_without_allocating() {
        let pool = Pool::new();
        let mut held: Vec<_> = (0..18).map(|_| pool.take().unwrap()).collect();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), pool.acquire())
                .await
                .is_err()
        );
        drop(held.pop());
        let b = pool.acquire().await.unwrap();
        assert_eq!(b.data.capacity(), 16440);
        drop(held);
        drop(b);
    }

    #[test]
    fn both_directions_match_vectors_and_reject_data_after_close() {
        let v = vector();
        let pool = Pool::new();
        for (name, role) in [("client", 0), ("server", 1)] {
            let prefix: [u8; 4] = hex::decode(
                v["expected"][format!("{name}_nonce_prefix")]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
            let sid = hex::decode(v["public"]["session_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let mut tx = Tx::new(key(&v, &format!("{name}_data_key")), prefix, sid, role).unwrap();
            let mut rx =
                Rx::new(key(&v, &format!("{name}_data_key")), prefix, sid, 1 - role).unwrap();
            let message =
                hex::decode(v["plaintexts"][format!("{name}_data")].as_str().unwrap()).unwrap();
            let wire = tx
                .data(Plaintext {
                    buffer: buf(&pool, &message),
                    start: 0,
                    length: message.len(),
                })
                .unwrap();
            assert_eq!(
                hex::encode(&wire.data),
                v["frames"][format!("{name}_data")].as_str().unwrap()
            );
            drop(rx.decode(buf(&pool, &wire.data)).unwrap());
            let close = tx.close(0).unwrap();
            assert_eq!(
                hex::encode(close),
                v["frames"][format!("{name}_close")].as_str().unwrap()
            );
            drop(rx.decode(buf(&pool, &close)).unwrap());
            assert!(rx.decode(buf(&pool, &wire.data)).is_err());
            assert!(tx
                .data(Plaintext {
                    buffer: buf(&pool, b"x"),
                    start: 0,
                    length: 1
                })
                .is_err());
        }
    }

    #[test]
    fn authenticated_unknown_close_and_receive_byte_overrun_poison_keys() {
        let pool = Pool::new();
        for bad_reason in [false, true] {
            let mut tx = Tx::new(Secret::zeros(), [0; 4], [1; 16], 0).unwrap();
            let mut rx = Rx::new(Secret::zeros(), [0; 4], [1; 16], 1).unwrap();
            let p = Plaintext {
                buffer: buf(&pool, &[3]),
                start: 0,
                length: 1,
            };
            let wire = if bad_reason {
                tx.encode(CLOSE, p).unwrap()
            } else {
                rx.bytes = MAX_BYTES;
                tx.data(p).unwrap()
            };
            assert!(rx.decode(wire).is_err());
            assert!(rx.closed && rx.key.is_none());
        }
    }

    #[test]
    fn failed_encryption_burns_sequence_and_cannot_retry() {
        let pool = Pool::new();
        let mut tx = Tx::new(Secret::zeros(), [0; 4], [1; 16], 0).unwrap();
        let mut buffer = buf(&pool, b"x");
        // Inject a broken capacity invariant without touching the AEAD or RNG.
        buffer.data.shrink_to_fit();
        assert!(matches!(
            tx.data(Plaintext {
                buffer,
                start: 0,
                length: 1
            }),
            Err(Error::Internal)
        ));
        assert_eq!(tx.seq, 1);
        assert!(tx.closed && tx.key.is_none());
        assert!(tx
            .data(Plaintext {
                buffer: buf(&pool, b"x"),
                start: 0,
                length: 1
            })
            .is_err());
        assert_eq!(tx.seq, 1);
    }
}
