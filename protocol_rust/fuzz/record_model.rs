//! Independent finite record-half model. Never linked into the production crate.
//! AEAD uses ring, independently of production's chacha20poly1305 implementation.
#![allow(dead_code)]
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde_json::{json, Value};

pub const MAX_INPUT: usize = 258;
pub const COUNT: u64 = 1 << 20;
pub const BUDGET: u64 = (1 << 30) - 1;
pub const LENGTHS: [usize; 7] = [0, 1, 2, 31, 16383, 16384, 16385];
pub const SID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Input,
    Closed,
    Authentication,
    Limit2,
}
impl Fault {
    pub fn label(self) -> &'static str {
        match self {
            Self::Input => "Input",
            Self::Closed => "Closed",
            Self::Authentication => "Authentication",
            Self::Limit2 => "Limit2",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub sequence: u64,
    pub bytes: u64,
    pub closed: bool,
    pub key_live: bool,
}
impl State {
    pub fn json(&self) -> Value {
        json!({"sequence":self.sequence,"bytes":self.bytes,
            "closed":self.closed,"key_live":self.key_live})
    }
    fn usable(&self) -> bool {
        !self.closed && self.key_live
    }
    fn reject<T>(&mut self, fault: Fault) -> Result<T, Fault> {
        self.closed = true;
        self.key_live = false;
        Err(fault)
    }
}

pub fn pattern(length: usize, first: u8, increment: u8) -> Vec<u8> {
    (0..length)
        .map(|i| first.wrapping_add((i as u8).wrapping_mul(increment)))
        .collect()
}

fn cipher() -> LessSafeKey {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap())
}
fn nonce(sequence: u64) -> Nonce {
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&[0xa0, 0xa1, 0xa2, 0xa3]);
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

pub fn seal(kind: u8, role: u8, sequence: u64, plaintext: &[u8], sid: [u8; 16]) -> Vec<u8> {
    let mut header = [0; 40];
    header[..4].copy_from_slice(b"SPK1");
    header[4..6].copy_from_slice(&1u16.to_be_bytes());
    header[6] = kind;
    header[7] = role;
    header[8..10].copy_from_slice(&0xf001u16.to_be_bytes());
    header[12..28].copy_from_slice(&sid);
    header[28..36].copy_from_slice(&sequence.to_be_bytes());
    header[36..40].copy_from_slice(&((plaintext.len() + 16) as u32).to_be_bytes());
    let mut body = plaintext.to_vec();
    cipher()
        .seal_in_place_append_tag(nonce(sequence), Aad::from(header), &mut body)
        .unwrap();
    let mut wire = header.to_vec();
    wire.extend(body);
    wire
}

pub struct Model {
    pub tx: State,
    pub rx: State,
    pub role: u8,
}
impl Model {
    pub fn new(scenario: u8, role: u8) -> Self {
        let (sequence, bytes) = match scenario {
            0 => (0, 0),
            1 => (COUNT - 2, 0),
            2 => (COUNT - 1, 0),
            3 => (COUNT, 0),
            4 => (0, BUDGET - 1),
            5 => (0, BUDGET),
            6 => (0, BUDGET - 16383),
            _ => panic!("unknown scenario"),
        };
        let tx = State {
            sequence,
            bytes,
            closed: false,
            key_live: true,
        };
        Self {
            rx: tx.clone(),
            tx,
            role,
        }
    }

    pub fn data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Fault> {
        if !self.tx.usable() {
            return Err(Fault::Closed);
        }
        if plaintext.is_empty() || plaintext.len() > 16384 {
            self.tx.key_live = false;
            return Err(Fault::Input);
        }
        if self.tx.sequence >= COUNT - 1 || self.tx.bytes + plaintext.len() as u64 > BUDGET {
            return Err(Fault::Limit2);
        }
        let wire = seal(16, self.role, self.tx.sequence, plaintext, SID);
        self.tx.sequence += 1;
        self.tx.bytes += plaintext.len() as u64;
        Ok(wire)
    }

    pub fn close(&mut self, reason: u8) -> Result<Vec<u8>, Fault> {
        if reason > 2 {
            return Err(Fault::Input);
        }
        if !self.tx.usable() {
            return Err(Fault::Closed);
        }
        if self.tx.sequence >= COUNT {
            self.tx.key_live = false;
            return Err(Fault::Input);
        }
        let wire = seal(17, self.role, self.tx.sequence, &[reason], SID);
        self.tx.sequence += 1;
        self.tx.closed = true;
        self.tx.key_live = false;
        Ok(wire)
    }

    pub fn receive(&mut self, raw: &[u8]) -> Result<(u8, Vec<u8>), Fault> {
        if !self.rx.usable() {
            return self.rx.reject(Fault::Closed);
        }
        if raw.len() < 40 {
            return self.rx.reject(Fault::Input);
        }
        let kind = raw[6];
        let length = u32::from_be_bytes(raw[36..40].try_into().unwrap()) as usize;
        let seq = u64::from_be_bytes(raw[28..36].try_into().unwrap());
        let length_valid = match kind {
            16 => (17..=16400).contains(&length),
            17 => length == 17,
            _ => false,
        };
        if &raw[..4] != b"SPK1"
            || raw[4..6] != [0, 1]
            || raw[8..12] != [0xf0, 1, 0, 0]
            || !length_valid
            || raw.len() != 40 + length
            || raw[7] != self.role
            || raw[12..28] != SID
            || seq != self.rx.sequence
            || seq >= COUNT
            || (kind == 16 && seq == COUNT - 1)
        {
            return self.rx.reject(Fault::Input);
        }
        let plaintext_length = length - 16;
        if kind == 16 && self.rx.bytes + plaintext_length as u64 > BUDGET {
            return self.rx.reject(Fault::Limit2);
        }
        let mut body = raw[40..].to_vec();
        let plaintext = match cipher().open_in_place(nonce(seq), Aad::from(&raw[..40]), &mut body) {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => return self.rx.reject(Fault::Authentication),
        };
        if kind == 17 && (plaintext.len() != 1 || plaintext[0] > 2) {
            return self.rx.reject(Fault::Input);
        }
        self.rx.sequence += 1;
        if kind == 16 {
            self.rx.bytes += plaintext.len() as u64;
        } else {
            self.rx.closed = true;
            self.rx.key_live = false;
        }
        Ok((kind, plaintext))
    }
}

pub fn mutate(mut wire: Vec<u8>, mutation: u8, choice: u8) -> Vec<u8> {
    let mutation = mutation % 8;
    if mutation == 2 {
        wire.push(choice);
        return wire;
    }
    if wire.is_empty() {
        return wire;
    }
    if mutation == 1 {
        wire.truncate(choice as usize % wire.len());
        return wire;
    }
    let index = match mutation {
        0 => choice as usize % wire.len(),
        3 => 7,
        4 => 12,
        5 => wire.len() - 1,
        6 => 35,
        7 => 6,
        _ => unreachable!(),
    };
    wire[index] ^= 1;
    wire
}

pub fn craft(state: &State, role: u8, a: u8, b: u8, c: u8) -> Vec<u8> {
    let kind = if a & 1 == 0 { 16 } else { 17 };
    let sequence = [
        state.sequence,
        state.sequence + 1,
        state.sequence.saturating_sub(1),
        COUNT - 1,
    ][((a >> 1) % 4) as usize];
    let mut sid = SID;
    if a & 16 != 0 {
        sid[0] ^= 1;
    }
    let plain = if kind == 17 {
        vec![c]
    } else {
        pattern(LENGTHS[(b % 7) as usize], c, 1)
    };
    let mut wire = seal(kind, role ^ ((a >> 3) & 1), sequence, &plain, sid);
    if a & 32 != 0 {
        *wire.last_mut().unwrap() ^= 1;
    }
    wire
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_data_then_close_and_replay_poison() {
        let mut m = Model::new(1, 0);
        let wire = m.data(b"a").unwrap();
        assert_eq!(m.receive(&wire).unwrap(), (16, b"a".to_vec()));
        assert_eq!(m.data(b"b"), Err(Fault::Limit2));
        let close = m.close(2).unwrap();
        assert_eq!(m.receive(&close).unwrap(), (17, vec![2]));
        assert_eq!(m.receive(&wire), Err(Fault::Closed));
        assert_eq!(m.rx.sequence, COUNT);
    }
    #[test]
    fn authentication_failure_poison_is_permanent() {
        let mut m = Model::new(0, 1);
        let wire = seal(16, 1, 0, b"message", SID);
        let bad = mutate(wire.clone(), 5, 0);
        assert_eq!(m.receive(&bad), Err(Fault::Authentication));
        assert_eq!(m.receive(&wire), Err(Fault::Closed));
        assert_eq!(m.rx.sequence, 0);
        assert_eq!(m.rx.bytes, 0);
    }
    #[test]
    fn invalid_authenticated_close_reason_is_input_failure() {
        let mut m = Model::new(0, 0);
        let wire = seal(17, 0, 0, &[3], SID);
        assert_eq!(m.receive(&wire), Err(Fault::Input));
        assert!(!m.rx.key_live);
    }
    #[test]
    fn byte_limit_allows_close_but_rx_failure_poisoned() {
        let mut m = Model::new(4, 0);
        assert!(m.data(b"a").is_ok());
        assert_eq!(m.data(b"b"), Err(Fault::Limit2));
        assert!(m.close(0).is_ok());
        let wire = seal(16, 0, 0, b"ab", SID);
        assert_eq!(m.receive(&wire), Err(Fault::Limit2));
        assert!(m.rx.closed);
    }
    #[test]
    fn invalid_data_and_close_reason_have_different_state_effects() {
        let mut m = Model::new(0, 0);
        assert_eq!(m.close(255), Err(Fault::Input));
        assert!(m.tx.usable());
        assert_eq!(m.data(&[]), Err(Fault::Input));
        assert!(!m.tx.key_live);
        assert!(!m.tx.closed);
        assert_eq!(m.close(255), Err(Fault::Input));
        assert_eq!(m.close(0), Err(Fault::Closed));
    }
}
