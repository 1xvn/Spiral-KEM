#![forbid(unsafe_code)]
use crate::{Error, Result};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Instant,
};
struct Bucket {
    active: usize,
    tokens: f64,
    last: Instant,
}
struct State {
    buckets: HashMap<IpAddr, Bucket>,
    active: usize,
    pending: usize,
}
#[derive(Clone)]
pub struct Admission {
    inner: Arc<Mutex<State>>,
}
pub struct Lease {
    inner: Arc<Mutex<State>>,
    peer: IpAddr,
    established: bool,
}
impl Default for Admission {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                buckets: HashMap::new(),
                active: 0,
                pending: 0,
            })),
        }
    }
}
impl Admission {
    pub fn acquire(&self, peer: IpAddr) -> Result<Lease> {
        let peer = match peer {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(peer),
            _ => peer,
        };
        let mut s = self.inner.lock().map_err(|_| Error::Internal)?;
        let now = Instant::now();
        s.buckets
            .retain(|_, b| b.active > 0 || now.duration_since(b.last).as_secs_f64() < 4.);
        if !s.buckets.contains_key(&peer) && s.buckets.len() >= 1024 {
            return Err(Error::QueueFull);
        }
        let global_full = s.active >= 64 || s.pending >= 32;
        let b = s.buckets.entry(peer).or_insert(Bucket {
            active: 0,
            tokens: 4.,
            last: now,
        });
        b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64()).min(4.);
        b.last = now;
        if global_full || b.active >= 4 || b.tokens < 1. {
            return Err(Error::QueueFull);
        }
        b.tokens -= 1.;
        b.active += 1;
        s.active += 1;
        s.pending += 1;
        Ok(Lease {
            inner: self.inner.clone(),
            peer,
            established: false,
        })
    }
    pub fn counts(&self) -> Result<(usize, usize)> {
        let s = self.inner.lock().map_err(|_| Error::Internal)?;
        Ok((s.active, s.pending))
    }
}
impl Lease {
    pub(crate) fn established(mut self) -> Result<Self> {
        if !self.established {
            self.inner.lock().map_err(|_| Error::Internal)?.pending -= 1;
            self.established = true;
        }
        Ok(self)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut s) = self.inner.lock() {
            s.active -= 1;
            if !self.established {
                s.pending -= 1;
            }
            if let Some(b) = s.buckets.get_mut(&self.peer) {
                b.active -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_release() {
        let a = Admission::default();
        let mut leases = Vec::new();
        for _ in 0..4 {
            leases.push(a.acquire("127.0.0.1".parse().unwrap()).unwrap());
        }
        assert!(a.acquire("127.0.0.1".parse().unwrap()).is_err());
        assert_eq!(a.counts().unwrap(), (4, 4));
        let l = leases.pop().unwrap().established().unwrap();
        assert_eq!(a.counts().unwrap(), (4, 3));
        let l = l.established().unwrap();
        assert_eq!(a.counts().unwrap(), (4, 3));
        drop(l);
        drop(leases);
        assert_eq!(a.counts().unwrap(), (0, 0));
    }
    #[test]
    fn mapped_ip_and_pending_cap() {
        let a = Admission::default();
        let mut held = Vec::new();
        for i in 1..=32 {
            held.push(
                a.acquire(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, i)))
                    .unwrap(),
            );
        }
        assert!(a.acquire("127.0.1.1".parse().unwrap()).is_err());
        drop(held);
        assert_eq!(a.counts().unwrap(), (0, 0));
        let held: Vec<_> = (0..4)
            .map(|_| a.acquire("127.0.1.1".parse().unwrap()).unwrap())
            .collect();
        assert!(a.acquire("::ffff:127.0.1.1".parse().unwrap()).is_err());
        drop(held);
        let a = Admission::default();
        let mut held = Vec::new();
        for i in 1..=64 {
            let l = a
                .acquire(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 2, i)))
                .unwrap();
            held.push(if i <= 32 { l.established().unwrap() } else { l });
        }
        assert_eq!(a.counts().unwrap(), (64, 32));
        assert!(a.acquire("127.0.2.65".parse().unwrap()).is_err());
        drop(held);
        assert_eq!(a.counts().unwrap(), (0, 0));
    }

    #[test]
    fn established_cap_is_independent_of_pending_cap() {
        let a = Admission::default();
        let mut held = Vec::new();
        for i in 1..=64 {
            held.push(
                a.acquire(IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, i)))
                    .unwrap()
                    .established()
                    .unwrap(),
            );
            assert_eq!(a.counts().unwrap(), (i as usize, 0));
        }
        let peer = "198.18.0.65".parse().unwrap();
        for _ in 0..16 {
            assert!(matches!(a.acquire(peer), Err(Error::QueueFull)));
            assert_eq!(a.counts().unwrap(), (64, 0));
        }
        drop(held.pop());
        assert_eq!(a.counts().unwrap(), (63, 0));
        held.push(a.acquire(peer).unwrap().established().unwrap());
        assert_eq!(a.counts().unwrap(), (64, 0));
        drop(held);
        assert_eq!(a.counts().unwrap(), (0, 0));
    }

    #[test]
    fn pending_rejection_preserves_peer_allowance_and_counters() {
        let a = Admission::default();
        let mut held: Vec<_> = (1..=32)
            .map(|i| {
                a.acquire(IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 1, i)))
                    .unwrap()
            })
            .collect();
        let peer = "198.18.1.33".parse().unwrap();
        for _ in 0..16 {
            assert!(matches!(a.acquire(peer), Err(Error::QueueFull)));
            assert_eq!(a.counts().unwrap(), (32, 32));
        }
        {
            let state = a.inner.lock().unwrap();
            let bucket = state.buckets.get(&peer).unwrap();
            assert_eq!(bucket.active, 0);
            assert_eq!(bucket.tokens, 4.);
        }
        held.truncate(28);
        for _ in 0..4 {
            held.push(a.acquire(peer).unwrap());
        }
        assert_eq!(a.counts().unwrap(), (32, 32));
        assert!(matches!(a.acquire(peer), Err(Error::QueueFull)));
        assert_eq!(a.counts().unwrap(), (32, 32));
        drop(held);
        assert_eq!(a.counts().unwrap(), (0, 0));
    }

    #[test]
    fn repeated_mixed_lease_drop_releases_all_counters() {
        let a = Admission::default();
        let shared = a.clone();
        for cycle in 0..64 {
            let mut held = Vec::new();
            for i in 0..8 {
                // Fresh peers avoid depending on wall-clock token refill.
                let lease = shared
                    .acquire(IpAddr::V4(std::net::Ipv4Addr::new(198, 19, cycle, i)))
                    .unwrap();
                held.push(if i % 2 == 0 {
                    lease.established().unwrap()
                } else {
                    lease
                });
            }
            assert_eq!(a.counts().unwrap(), (8, 4));
            for remaining in (0..8).rev() {
                drop(held.pop());
                assert_eq!(a.counts().unwrap(), (remaining, remaining / 2));
            }
            let state = a.inner.lock().unwrap();
            assert!(state.buckets.values().all(|bucket| bucket.active == 0));
        }
        assert_eq!(shared.counts().unwrap(), (0, 0));
    }
}
