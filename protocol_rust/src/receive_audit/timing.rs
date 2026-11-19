//! Opt-in libtest diagnostic with generated public fixtures only.
use super::{buffer, Pool, Rx, Secret, Tx, SID};
use crate::{schedule::digest, secret::Plaintext, wire::DATA, Error};
use std::{hint::black_box, io::{BufWriter, Write}, path::PathBuf, time::Instant};

const PAIRS: usize = 2000;
const WARMUP: usize = 128;

#[derive(Clone, Copy, PartialEq)]
enum Comparison { Positive, Sham, Key }

impl Comparison {
    fn label(self) -> &'static str {
        match self { Self::Positive => "positive", Self::Sham => "sham", Self::Key => "key" }
    }
}

fn owner<const N: usize>(bytes: &[u8; N]) -> Secret<N> {
    let mut result = Secret::zeros();
    result.bytes_mut().copy_from_slice(bytes);
    result
}

fn fixture_bytes(domain: u8, id: u32) -> [u8; 32] {
    let mut label = [domain; 5];
    label[1..].copy_from_slice(&id.to_be_bytes());
    digest(&label)
}

fn observation(key: &[u8; 32], prefix: &[u8; 4], message: &[u8; 64], bad_tag: bool, extra_work: bool) -> u128 {
    let pool = Pool::new();
    let mut tx = Tx::new(owner(key), owner(prefix), SID, 0).unwrap();
    let mut frame = tx.data(Plaintext {
        buffer: buffer(&pool, message),
        start: 0,
        length: message.len(),
    }).unwrap();
    if bad_tag {
        *frame.data.last_mut().unwrap() ^= 1;
    }
    let mut rx = Rx::new(owner(key), owner(prefix), SID, 1).unwrap();
    let input = black_box(frame);
    let start = Instant::now();
    if extra_work {
        for _ in 0..128 {
            std::hint::spin_loop();
        }
    }
    let result = black_box(rx.decode(input));
    let ns = start.elapsed().as_nanos();
    match (bad_tag, result) {
        (false, Ok((DATA, plain))) => assert_eq!(plain.as_bytes(), message),
        (true, Err(Error::Authentication)) => (),
        _ => panic!("unexpected record decision"),
    }
    ns
}

#[test]
#[ignore = "run the bounded receive timing collector on a pinned CPU"]
fn collect() {
    let path = PathBuf::from(std::env::var_os("SPIRAL_TIMING_CSV").unwrap());
    let trial: u32 = std::env::var("SPIRAL_TIMING_TRIAL").unwrap().parse().unwrap();
    assert!(trial < 2);
    let fixed = digest(b"spiral timing public fixed fixture");
    let mut rows = Vec::new();
    // Reverse stream order in trial two. Use unique fixture IDs across streams and trials.
    for index in 0..6u32 {
        let stream = if trial == 0 { index } else { 5 - index };
        let bad_tag = stream >= 3;
        let comparison = [Comparison::Positive, Comparison::Sham, Comparison::Key][(stream % 3) as usize];
        for pair in 0..(WARMUP + PAIRS) {
            let id = (trial * 6 + stream) * 4096 + pair as u32;
            let prefix = id.to_be_bytes();
            let varying = fixture_bytes(1, id);
            let message_half = fixture_bytes(2, id);
            let mut message = [0; 64];
            message[..32].copy_from_slice(&message_half);
            message[32..].copy_from_slice(&fixture_bytes(3, id));
            // Balance AB / BA within each consecutive two-pair block.
            let first_b = ((fixture_bytes(4, id & !1)[0] & 1) ^ (id as u8 & 1)) != 0;
            for (position, b) in [first_b, !first_b].into_iter().enumerate() {
                let key = if comparison == Comparison::Key && b { &varying } else { &fixed };
                let ns = observation(key, &prefix, &message, bad_tag, comparison == Comparison::Positive && b);
                if pair >= WARMUP {
                    rows.push((bad_tag, comparison, pair - WARMUP, position, b, ns));
                }
            }
        }
    }
    let mut out = BufWriter::new(std::fs::File::create_new(path).unwrap());
    writeln!(out, "decision,comparison,pair,position,class,ns").unwrap();
    for (bad, comp, pair, pos, b, elapsed) in rows {
        writeln!(out, "{},{},{},{},{},{}", if bad { "reject" } else { "accept" },
                 comp.label(), pair, pos, if b { "B" } else { "A" }, elapsed).unwrap();
    }
    out.flush().unwrap();
}
