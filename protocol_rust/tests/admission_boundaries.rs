//! Public admission API checks, separate from the real-socket load campaign.
#![forbid(unsafe_code)]

use spiral_protocol::{admission::Admission, Error};
use std::{
    net::IpAddr,
    thread,
    time::{Duration, Instant},
};

fn wait_for_token_refill() {
    let end = Instant::now() + Duration::from_millis(1100);
    loop {
        let now = Instant::now();
        if now >= end {
            return;
        }
        thread::sleep(end - now);
    }
}

#[test]
fn per_ip_active_cap_rejects_with_refilled_token() {
    let admission = Admission::default();
    let peer: IpAddr = "198.18.10.1".parse().unwrap();
    let held: Vec<_> = (0..4).map(|_| admission.acquire(peer).unwrap()).collect();
    assert_eq!(admission.counts().unwrap(), (4, 4));

    // At least one token is available regardless of scheduling or oversleep.
    // Four active/pending leases are below both global admission limits.
    wait_for_token_refill();
    assert!(matches!(admission.acquire(peer), Err(Error::QueueFull)));
    assert_eq!(admission.counts().unwrap(), (4, 4));
    drop(held);
    assert_eq!(admission.counts().unwrap(), (0, 0));

    // The active-cap rejection did not consume the replenished token.
    let recovered = admission.acquire(peer).unwrap();
    assert_eq!(admission.counts().unwrap(), (1, 1));
    drop(recovered);
    assert_eq!(admission.counts().unwrap(), (0, 0));
}

#[test]
fn per_ip_token_bucket_rejects_below_active_cap_and_refills() {
    let peer: IpAddr = "198.18.10.2".parse().unwrap();
    for _ in 0..8 {
        let admission = Admission::default();
        let started = Instant::now();
        let mut held: Vec<_> = (0..4).map(|_| admission.acquire(peer).unwrap()).collect();
        let remaining = held.pop().unwrap();
        drop(held);
        assert_eq!(admission.counts().unwrap(), (1, 1));
        let rejection = admission.acquire(peer);

        // Assert rate rejection only when the whole observation took less than
        // one refill interval. A scheduler stall gets a fresh bucket and retry.
        if started.elapsed() >= Duration::from_secs(1) {
            drop(rejection);
            drop(remaining);
            assert_eq!(admission.counts().unwrap(), (0, 0));
            continue;
        }
        assert!(matches!(rejection, Err(Error::QueueFull)));
        assert_eq!(admission.counts().unwrap(), (1, 1));

        wait_for_token_refill();
        let recovered = admission.acquire(peer).unwrap();
        assert_eq!(admission.counts().unwrap(), (2, 2));
        drop(recovered);
        drop(remaining);
        assert_eq!(admission.counts().unwrap(), (0, 0));
        return;
    }
    panic!("scheduler did not provide a sub-second rate observation window in eight fresh attempts");
}
