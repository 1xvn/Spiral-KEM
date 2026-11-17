#![forbid(unsafe_code)]
use crate::{Error, Result};
#[cfg(feature = "flow-diagnostics")]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;
pub(crate) const CAPACITY: usize = 16_440;
pub(crate) const LIMIT: usize = 18;
struct State {
    free: Vec<Vec<u8>>,
    allocated: usize,
}
pub(crate) struct Pool {
    state: Mutex<State>,
    available: tokio::sync::Notify,
    #[cfg(feature = "flow-diagnostics")]
    flow: FlowCounters,
}
#[cfg(feature = "flow-diagnostics")]
#[derive(Default)]
struct FlowCounters {
    active_sends: AtomicUsize,
    send_slot_waiters: AtomicUsize,
    buffer_waiters: AtomicUsize,
    receive_delivery_waiters: AtomicUsize,
}
#[cfg(feature = "flow-diagnostics")]
pub(crate) enum FlowCounter {
    ActiveSend,
    SendSlotWaiter,
    BufferWaiter,
    ReceiveDeliveryWaiter,
}
#[cfg(feature = "flow-diagnostics")]
pub(crate) struct FlowGuard<'a>(&'a AtomicUsize);
#[cfg(feature = "flow-diagnostics")]
impl Drop for FlowGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
#[cfg(feature = "flow-diagnostics")]
pub(crate) struct PoolSnapshot {
    pub allocated: usize,
    pub free: usize,
    pub active_sends: usize,
    pub send_slot_waiters: usize,
    pub buffer_waiters: usize,
    pub receive_delivery_waiters: usize,
}
impl Pool {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            available: tokio::sync::Notify::new(),
            state: Mutex::new(State {
                free: Vec::new(),
                allocated: 0,
            }),
            #[cfg(feature = "flow-diagnostics")]
            flow: FlowCounters::default(),
        })
    }
    pub fn take(self: &Arc<Self>) -> Result<Buffer> {
        let mut state = self.state.lock().map_err(|_| Error::Internal)?;
        let data = if let Some(v) = state.free.pop() {
            v
        } else {
            if state.allocated >= LIMIT {
                return Err(Error::QueueFull);
            }
            state.allocated += 1;
            Vec::with_capacity(CAPACITY)
        };
        Ok(Buffer {
            data,
            pool: Some(self.clone()),
        })
    }
    pub async fn acquire(self: &Arc<Self>) -> Result<Buffer> {
        loop {
            let ready = self.available.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            match self.take() {
                Ok(b) => return Ok(b),
                Err(Error::QueueFull) => {
                    #[cfg(feature = "flow-diagnostics")]
                    let _waiting = self.track(FlowCounter::BufferWaiter);
                    ready.await;
                }
                Err(e) => return Err(e),
            }
        }
    }
    #[cfg(feature = "flow-diagnostics")]
    pub(crate) fn track(&self, counter: FlowCounter) -> FlowGuard<'_> {
        let counter = match counter {
            FlowCounter::ActiveSend => &self.flow.active_sends,
            FlowCounter::SendSlotWaiter => &self.flow.send_slot_waiters,
            FlowCounter::BufferWaiter => &self.flow.buffer_waiters,
            FlowCounter::ReceiveDeliveryWaiter => &self.flow.receive_delivery_waiters,
        };
        counter.fetch_add(1, Ordering::AcqRel);
        FlowGuard(counter)
    }
    #[cfg(feature = "flow-diagnostics")]
    pub(crate) fn snapshot(&self) -> Result<PoolSnapshot> {
        let state = self.state.lock().map_err(|_| Error::Internal)?;
        Ok(PoolSnapshot {
            allocated: state.allocated,
            free: state.free.len(),
            active_sends: self.flow.active_sends.load(Ordering::Acquire),
            send_slot_waiters: self.flow.send_slot_waiters.load(Ordering::Acquire),
            buffer_waiters: self.flow.buffer_waiters.load(Ordering::Acquire),
            receive_delivery_waiters: self.flow.receive_delivery_waiters.load(Ordering::Acquire),
        })
    }
}
pub(crate) struct Buffer {
    pub data: Vec<u8>,
    pool: Option<Arc<Pool>>,
}
impl Buffer {
    pub fn close_frame() -> Self {
        Self {
            data: Vec::with_capacity(57),
            pool: None,
        }
    }
}
impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        // Vec's Zeroize implementation clears the entire capacity, including
        // truncated plaintext/tag space, and preserves the allocation for reuse.
        self.data.zeroize();
        if let Some(pool) = &self.pool {
            if let Ok(mut s) = pool.state.lock() {
                s.free.push(std::mem::take(&mut self.data));
            }
            pool.available.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Wake, Waker},
    };

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn canceled_waiter_preserves_return_notification_and_pool_bound() {
        let pool = Pool::new();
        let mut held: Vec<_> = (0..18).map(|_| pool.take().unwrap()).collect();
        let wake_count = Arc::new(WakeCount::default());
        let waker = Waker::from(wake_count.clone());
        let mut context = Context::from_waker(&waker);
        let mut canceled = Box::pin(pool.acquire());
        let mut waiting = Box::pin(pool.acquire());
        assert!(matches!(canceled.as_mut().poll(&mut context), Poll::Pending));
        assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Pending));
        drop(canceled);
        assert_eq!(pool.state.lock().unwrap().allocated, 18);
        assert!(matches!(pool.take(), Err(Error::QueueFull)));

        drop(held.pop());
        assert!(wake_count.0.load(Ordering::Relaxed) > 0);
        let returned = match waiting.as_mut().poll(&mut context) {
            Poll::Ready(Ok(buffer)) => buffer,
            _ => panic!("returned buffer did not wake the surviving waiter"),
        };
        assert!(returned.data.is_empty());
        assert_eq!(returned.data.capacity(), CAPACITY);
        assert!(matches!(pool.take(), Err(Error::QueueFull)));
        drop(waiting);
        drop(returned);
        drop(held);
        let state = pool.state.lock().unwrap();
        assert_eq!(state.allocated, 18);
        assert_eq!(state.free.len(), 18);
    }

    #[cfg(feature = "flow-diagnostics")]
    #[test]
    fn diagnostic_buffer_waiters_clear_on_cancellation_and_return() {
        let pool = Pool::new();
        let mut held: Vec<_> = (0..LIMIT).map(|_| pool.take().unwrap()).collect();
        let wake_count = Arc::new(WakeCount::default());
        let waker = Waker::from(wake_count);
        let mut context = Context::from_waker(&waker);
        let mut canceled = Box::pin(pool.acquire());
        let mut waiting = Box::pin(pool.acquire());
        assert!(canceled.as_mut().poll(&mut context).is_pending());
        assert!(waiting.as_mut().poll(&mut context).is_pending());
        let snapshot = pool.snapshot().unwrap();
        assert_eq!(
            (snapshot.allocated, snapshot.free, snapshot.buffer_waiters),
            (18, 0, 2)
        );
        drop(canceled);
        assert_eq!(pool.snapshot().unwrap().buffer_waiters, 1);
        drop(held.pop());
        let returned = match waiting.as_mut().poll(&mut context) {
            Poll::Ready(Ok(buffer)) => buffer,
            _ => panic!("diagnostic waiter did not acquire the returned buffer"),
        };
        assert_eq!(pool.snapshot().unwrap().buffer_waiters, 0);
        drop(waiting);
        drop(returned);
        drop(held);
        let snapshot = pool.snapshot().unwrap();
        assert_eq!((snapshot.allocated, snapshot.free), (LIMIT, LIMIT));
    }
}
