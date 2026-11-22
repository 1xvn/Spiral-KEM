//! Opt-in libtest diagnostic with generated public fixtures only.
use super::{buffer, Pool, Rx, Secret, Tx, SID};
use crate::{schedule::digest, secret::Plaintext, wire::DATA, Error};
use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
use serde_json::{json, Value};
use std::{
    fs::{read_to_string, File},
    hint::black_box,
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

const PAIRS: usize = 2000;
const WARMUP: usize = 128;

#[derive(Clone, Copy, PartialEq)]
enum Comparison {
    Positive,
    PositiveLarge,
    Sham,
    Key,
}

impl Comparison {
    fn label(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::PositiveLarge => "positive_large",
            Self::Sham => "sham",
            Self::Key => "key",
        }
    }

    fn spin_hints(self) -> usize {
        match self {
            Self::Positive => 128,
            Self::PositiveLarge => 512,
            _ => 0,
        }
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

fn thread_cpu_ns() -> Option<u128> {
    let ts = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let seconds = u128::try_from(ts.tv_sec).ok()?;
    let nanos = u128::try_from(ts.tv_nsec).ok()?;
    (nanos < 1_000_000_000).then_some(seconds * 1_000_000_000 + nanos)
}

fn schedstat() -> Option<[u64; 3]> {
    read_to_string("/proc/thread-self/schedstat")
        .ok()?
        .split_ascii_whitespace()
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .ok()?
        .try_into()
        .ok()
}

fn observation(
    key: &[u8; 32],
    prefix: &[u8; 4],
    message: &[u8; 64],
    bad_tag: bool,
    spin_hints: usize,
) -> (u128, Option<u128>) {
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
    let cpu_start = thread_cpu_ns();
    let start = Instant::now();
    for _ in 0..spin_hints {
        std::hint::spin_loop();
    }
    let result = black_box(rx.decode(input));
    let ns = start.elapsed().as_nanos();
    let cpu_ns = thread_cpu_ns().zip(cpu_start).and_then(|(end, begin)| end.checked_sub(begin));
    match (bad_tag, result) {
        (false, Ok((DATA, plain))) => assert_eq!(plain.as_bytes(), message),
        (true, Err(Error::Authentication)) => (),
        _ => panic!("unexpected record decision"),
    }
    (ns, cpu_ns)
}

#[test]
#[ignore = "run the bounded receive timing collector on a pinned CPU"]
fn collect() {
    let path = PathBuf::from(std::env::var_os("SPIRAL_TIMING_CSV").unwrap());
    let trial: u32 = std::env::var("SPIRAL_TIMING_TRIAL").unwrap().parse().unwrap();
    assert!(trial < 2);
    let fixed = digest(b"spiral timing public fixed fixture");
    let mut rows = Vec::new();
    let mut streams: Vec<Value> = Vec::new();
    use Comparison::{Key, Positive, PositiveLarge, Sham};
    let reject_controls = std::env::var("SPIRAL_TIMING_REJECT_CONTROLS").as_deref() == Ok("1");
    let cases: &[(bool, Comparison)] = if reject_controls {
        &[(true, Positive), (true, PositiveLarge), (true, Sham), (true, Key)]
    } else {
        &[
            (false, Positive), (false, Sham), (false, Key),
            (true, Positive), (true, Sham), (true, Key),
        ]
    };
    // Reverse stream order in trial two, with separate fixture IDs per mode.
    for index in 0..cases.len() {
        let stream = if trial == 0 { index } else { cases.len() - 1 - index };
        let (bad_tag, comparison) = cases[stream];
        let stream_id = trial * 6 + stream as u32 + if reject_controls { 12 } else { 0 };
        let before = schedstat();
        for pair in 0..(WARMUP + PAIRS) {
            let id = stream_id * 4096 + pair as u32;
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
                let spin_hints = if b { comparison.spin_hints() } else { 0 };
                let (ns, cpu_ns) = observation(key, &prefix, &message, bad_tag, spin_hints);
                if pair >= WARMUP {
                    rows.push((bad_tag, comparison, pair - WARMUP, position, b, ns, cpu_ns));
                }
            }
        }
        streams.push(json!({
            "decision": if bad_tag { "reject" } else { "accept" },
            "comparison": comparison.label(),
            "before": before,
            "after": schedstat(),
        }));
    }
    let scheduler_file = File::create_new(path.with_extension("scheduler.json")).unwrap();
    let schedstats_enabled = read_to_string("/proc/sys/kernel/sched_schedstats").ok()
        .and_then(|s| match s.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        });
    serde_json::to_writer(scheduler_file, &json!({
        "schedstats_enabled": schedstats_enabled,
        "streams": streams,
    })).unwrap();

    let mut out = BufWriter::new(File::create_new(path).unwrap());
    writeln!(out, "decision,comparison,pair,position,class,ns,thread_cpu_ns").unwrap();
    for (bad, comp, pair, pos, b, elapsed, cpu_ns) in rows {
        write!(out, "{},{},{},{},{},{},", if bad { "reject" } else { "accept" },
               comp.label(), pair, pos, if b { "B" } else { "A" }, elapsed).unwrap();
        if let Some(cpu_ns) = cpu_ns {
            write!(out, "{cpu_ns}").unwrap();
        }
        writeln!(out).unwrap();
    }
    out.flush().unwrap();
}
