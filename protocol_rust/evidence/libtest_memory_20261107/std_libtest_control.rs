use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    let mode = std::env::args().nth(1).expect("a control mode is required");
    match mode.as_str() {
        "empty-main" => {},
        "thread-current" => {
            std::hint::black_box(thread::current().id());
        },
        "thread-join" => {
            let value = thread::spawn(|| 73_u32).join().expect("worker panicked");
            assert_eq!(value, 73);
        },
        "channel-roundtrip" => {
            let (gate_tx, gate_rx) = mpsc::sync_channel::<()>(0);
            let (value_tx, value_rx) = mpsc::channel::<u32>();
            let worker = thread::spawn(move || {
                gate_rx.recv().expect("gate disconnected");
                value_tx.send(73).expect("value receiver disconnected");
            });
            // The sender cannot publish until this receive has blocked and
            // timed out. This exercises the main thread's channel context
            // even when scheduling would otherwise take a fast receive path.
            assert!(matches!(value_rx.recv_timeout(Duration::from_millis(10)),
                             Err(mpsc::RecvTimeoutError::Timeout)));
            gate_tx.send(()).expect("gate receiver disconnected");
            assert_eq!(value_rx.recv().expect("value sender disconnected"), 73);
            worker.join().expect("worker panicked");
        },
        _ => panic!("unknown control mode"),
    }
    println!("CONTROL_COMPLETED {}", mode);
}

#[cfg(test)]
mod control {
    #[test]
    fn empty() {}
}
