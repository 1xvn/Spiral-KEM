#![forbid(unsafe_code)]
use crate::{Error, Result};
pub const HEADER: usize = 40;
pub const MAX_DATA: usize = 16_384;
pub const MAX_RECORDS: u64 = 1 << 20;
pub const SUITE: u16 = 0xf001;
pub const DATA: u8 = 0x10;
pub const CLOSE: u8 = 0x11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub role: u8,
    pub sid: [u8; 16],
    pub sequence: u64,
    pub length: usize,
}
impl Header {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() != HEADER
            || &raw[..4] != b"SPK1"
            || raw[4..6] != [0, 1]
            || raw[10..12] != [0, 0]
        {
            return Err(Error::Input);
        }
        let h = Self {
            kind: raw[6],
            role: raw[7],
            sid: raw[12..28].try_into().unwrap(),
            sequence: u64::from_be_bytes(raw[28..36].try_into().unwrap()),
            length: u32::from_be_bytes(raw[36..40].try_into().unwrap()) as usize,
        };
        let (min, max) = match h.kind {
            1 => (75, 418),
            2 => (940, 940),
            3 => (1192, 1192),
            4 => (32, 32),
            DATA => (17, 16400),
            CLOSE => (17, 17),
            _ => return Err(Error::Input),
        };
        if h.role > 1
            || !(min..=max).contains(&h.length)
            || u16::from_be_bytes(raw[8..10].try_into().unwrap())
                != if h.kind == 1 { 0 } else { SUITE }
        {
            return Err(Error::Input);
        }
        if (h.kind == 1) == (h.sid != [0; 16]) {
            return Err(Error::Input);
        }
        match h.kind {
            1 | 2 if h.role != h.kind - 1 || h.sequence != 0 => return Err(Error::Input),
            3 | 4 if h.role != h.kind - 3 || h.sequence != 1 => return Err(Error::Input),
            DATA | CLOSE
                if h.sequence >= MAX_RECORDS
                    || (h.kind == DATA && h.sequence == MAX_RECORDS - 1) =>
            {
                return Err(Error::Input)
            }
            _ => {}
        }
        Ok(h)
    }
    pub fn encode(self) -> Result<[u8; HEADER]> {
        let mut raw = [0; HEADER];
        raw[..4].copy_from_slice(b"SPK1");
        raw[4..6].copy_from_slice(&1u16.to_be_bytes());
        raw[6] = self.kind;
        raw[7] = self.role;
        raw[8..10].copy_from_slice(&(if self.kind == 1 { 0 } else { SUITE }).to_be_bytes());
        raw[12..28].copy_from_slice(&self.sid);
        raw[28..36].copy_from_slice(&self.sequence.to_be_bytes());
        raw[36..40].copy_from_slice(
            &u32::try_from(self.length)
                .map_err(|_| Error::Input)?
                .to_be_bytes(),
        );
        Self::parse(&raw)?;
        Ok(raw)
    }
    pub fn expect(
        &self,
        kind: Option<u8>,
        role: u8,
        sid: Option<[u8; 16]>,
        sequence: u64,
    ) -> Result<()> {
        if kind.is_some_and(|k| k != self.kind)
            || role != self.role
            || sid.is_some_and(|s| s != self.sid)
            || sequence != self.sequence
        {
            return Err(Error::Input);
        }
        Ok(())
    }
}

pub fn frame(kind: u8, role: u8, sid: [u8; 16], sequence: u64, payload: &[u8]) -> Result<Vec<u8>> {
    let h = Header {
        kind,
        role,
        sid,
        sequence,
        length: payload.len(),
    }
    .encode()?;
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(&h);
    out.extend_from_slice(payload);
    Ok(out)
}
pub fn parse(raw: &[u8]) -> Result<(Header, &[u8])> {
    if raw.len() < HEADER {
        return Err(Error::Input);
    }
    let h = Header::parse(&raw[..HEADER])?;
    if raw.len() != HEADER + h.length {
        return Err(Error::Input);
    }
    Ok((h, &raw[HEADER..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixtures() -> Vec<Vec<u8>> {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../protocol_v01/tests/fixtures/test_vectors_v0.1.json"
        ))
        .unwrap();
        v["frames"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
            .collect()
    }
    #[test]
    fn all_fixture_roundtrips_and_truncations() {
        for raw in fixtures() {
            let (h, p) = parse(&raw).unwrap();
            assert_eq!(frame(h.kind, h.role, h.sid, h.sequence, p).unwrap(), raw);
            for n in 0..raw.len() {
                assert!(parse(&raw[..n]).is_err());
            }
        }
    }
    #[test]
    fn every_header_bit_under_connection_expectation() {
        for raw in fixtures() {
            let (h, _) = parse(&raw).unwrap();
            for i in 0..HEADER {
                for b in 0..8 {
                    let mut bad = raw.clone();
                    bad[i] ^= 1 << b;
                    let accepted = parse(&bad)
                        .and_then(|(x, _)| x.expect(Some(h.kind), h.role, Some(h.sid), h.sequence));
                    assert!(accepted.is_err());
                }
            }
        }
    }
    #[test]
    fn deterministic_mutation_corpus_canonical_if_accepted() {
        let sources = fixtures();
        let mut rng = 20261106u32;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            rng
        };
        for i in 0..4096 {
            let mut b = sources[next() as usize % sources.len()].clone();
            match i % 4 {
                0 => {
                    let p = next() as usize % b.len();
                    b[p] ^= (next() as u8) | 1;
                }
                1 => {
                    let n = next() as usize % b.len();
                    b.truncate(n);
                }
                2 => b.extend_from_slice(&next().to_be_bytes()),
                _ => b[36..40].copy_from_slice(&next().to_be_bytes()),
            }
            if let Ok((h, p)) = parse(&b) {
                assert_eq!(frame(h.kind, h.role, h.sid, h.sequence, p).unwrap(), b);
            }
        }
    }
    #[test]
    fn length_bombs_and_reserved_close() {
        let mut h = Header {
            kind: 3,
            role: 0,
            sid: [1; 16],
            sequence: 1,
            length: 1192,
        }
        .encode()
        .unwrap();
        for n in [0u32, 1191, 1193, 16441, 1 << 20, 0x7fffffff, 0xffffffff] {
            h[36..40].copy_from_slice(&n.to_be_bytes());
            assert!(Header::parse(&h).is_err());
        }
        assert!(Header {
            kind: DATA,
            role: 0,
            sid: [1; 16],
            sequence: MAX_RECORDS - 1,
            length: 17
        }
        .encode()
        .is_err());
        assert!(Header {
            kind: CLOSE,
            role: 0,
            sid: [1; 16],
            sequence: MAX_RECORDS - 1,
            length: 17
        }
        .encode()
        .is_ok());
    }
}
