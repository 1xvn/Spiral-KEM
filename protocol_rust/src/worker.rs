#![forbid(unsafe_code)]
use crate::{ffi, secret::Secret, Error, Result};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

#[derive(Default)]
struct Counters {
    live: AtomicUsize,
    executed: AtomicU64,
    rejected: AtomicU64,
}
#[derive(Debug, Clone, Copy)]
pub struct Metrics {
    pub live_keys: usize,
    pub executed: u64,
    pub rejected: u64,
}
struct Inner {
    senders: Vec<mpsc::SyncSender<Job>>,
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
    stop: Arc<AtomicBool>,
    slots: Arc<Semaphore>,
    key_slots: Arc<Semaphore>,
    next: AtomicUsize,
    stats: Arc<Counters>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}
#[derive(Clone)]
pub struct KemPool {
    inner: Arc<Inner>,
}

/// Opaque worker-local lease; neither raw C address nor key bytes are exposed.
pub(crate) struct KemLease {
    inner: Arc<Inner>,
    worker: usize,
    id: u64,
    cancel: Arc<AtomicBool>,
}
impl Drop for KemLease {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}
struct CancelGuard {
    flag: Arc<AtomicBool>,
    armed: bool,
}
impl Drop for CancelGuard {
    fn drop(&mut self) {
        if self.armed {
            self.flag.store(true, Ordering::Release);
        }
    }
}

enum Request {
    Generate(OwnedSemaphorePermit),
    Encaps(Box<[u8; 808]>),
    Decaps(u64, Box<[u8; 1160]>),
    #[cfg(test)]
    Hold(Duration),
}
enum Response {
    Generated(u64, Box<[u8; 808]>),
    Encapsulated(Box<[u8; 1160]>, Secret<32>),
    Decapsulated(Secret<32>),
    #[cfg(test)]
    Held,
}
struct Job {
    request: Request,
    reply: oneshot::Sender<Result<Response>>,
    started: oneshot::Sender<()>,
    cancel: Arc<AtomicBool>,
    deadline: Instant,
    queue_deadline: Instant,
    _slot: OwnedSemaphorePermit,
}
struct Stored {
    key: Option<ffi::NativeKey>,
    cancel: Arc<AtomicBool>,
    expires: Instant,
    _slot: OwnedSemaphorePermit,
    stats: Arc<Counters>,
}
impl Drop for Stored {
    fn drop(&mut self) {
        drop(self.key.take());
        self.stats.live.fetch_sub(1, Ordering::AcqRel);
    }
}

fn worker(rx: mpsc::Receiver<Job>, stop: Arc<AtomicBool>, stats: Arc<Counters>) {
    let mut keys: HashMap<u64, Stored> = HashMap::new();
    let mut next = 0u64;
    while !stop.load(Ordering::Acquire) {
        keys.retain(|_, k| !k.cancel.load(Ordering::Acquire) && Instant::now() < k.expires);
        let job = match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(j) => j,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let _ = job.started.send(());
        if stop.load(Ordering::Acquire)
            || job.cancel.load(Ordering::Acquire)
            || Instant::now() >= job.deadline
            || Instant::now() >= job.queue_deadline
        {
            let _ = job.reply.send(Err(Error::Deadline));
            continue;
        }
        stats.executed.fetch_add(1, Ordering::Relaxed);
        let result = (|| -> Result<Response> {
            match job.request {
                Request::Generate(slot) => {
                    let (pk, key) = ffi::NativeKey::generate()?;
                    if job.cancel.load(Ordering::Acquire) || Instant::now() >= job.deadline {
                        return Err(Error::Deadline);
                    }
                    next = next.checked_add(1).ok_or(Error::Internal)?;
                    stats.live.fetch_add(1, Ordering::AcqRel);
                    keys.insert(
                        next,
                        Stored {
                            key: Some(key),
                            cancel: job.cancel.clone(),
                            expires: job.deadline,
                            _slot: slot,
                            stats: stats.clone(),
                        },
                    );
                    Ok(Response::Generated(next, pk))
                }
                Request::Encaps(pk) => {
                    let (ct, ss) = ffi::encapsulate(&pk)?;
                    Ok(Response::Encapsulated(ct, ss))
                }
                Request::Decaps(id, ct) => {
                    let mut stored = keys.remove(&id).ok_or(Error::UsedKey)?;
                    if !Arc::ptr_eq(&stored.cancel, &job.cancel)
                        || stored.cancel.load(Ordering::Acquire)
                        || Instant::now() >= stored.expires
                    {
                        return Err(Error::UsedKey);
                    }
                    let ss = stored.key.take().ok_or(Error::UsedKey)?.decapsulate(&ct)?;
                    drop(stored);
                    Ok(Response::Decapsulated(ss))
                }
                #[cfg(test)]
                Request::Hold(d) => {
                    thread::sleep(d);
                    Ok(Response::Held)
                }
            }
        })();
        if job.cancel.load(Ordering::Acquire)
            || stop.load(Ordering::Acquire)
            || Instant::now() >= job.deadline
        {
            drop(result);
            let _ = job.reply.send(Err(Error::Deadline));
        } else {
            let _ = job.reply.send(result);
        }
    }
    drop(keys); // All keys are destroyed on their owning thread.
    while let Ok(job) = rx.try_recv() {
        let _ = job.reply.send(Err(Error::Closed));
    }
}

impl KemPool {
    pub fn new(workers: usize) -> Result<Self> {
        Self::with_capacity(workers, 32)
    }
    pub fn default_workers() -> usize {
        std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1).clamp(1, 2))
    }
    fn with_capacity(workers: usize, capacity: usize) -> Result<Self> {
        if !(1..=4).contains(&workers) || !(1..=32).contains(&capacity) {
            return Err(Error::Input);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Counters::default());
        let mut senders = Vec::new();
        let mut threads = Vec::new();
        for i in 0..workers {
            let (tx, rx) = mpsc::sync_channel(capacity);
            let s = stop.clone();
            let c = stats.clone();
            match thread::Builder::new()
                .name(format!("spiral-kem-{i}"))
                .spawn(move || worker(rx, s, c))
            {
                Ok(handle) => {
                    senders.push(tx);
                    threads.push(handle);
                }
                Err(_) => {
                    stop.store(true, Ordering::Release);
                    for h in threads {
                        let _ = h.join();
                    }
                    return Err(Error::Internal);
                }
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                senders,
                threads: Mutex::new(threads),
                stop,
                slots: Arc::new(Semaphore::new(capacity)),
                key_slots: Arc::new(Semaphore::new(32)),
                next: AtomicUsize::new(0),
                stats,
            }),
        })
    }
    async fn run(
        &self,
        worker: usize,
        request: Request,
        flag: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Response> {
        let mut guard = CancelGuard {
            flag: flag.clone(),
            armed: true,
        };
        if self.inner.stop.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        let slot = self.inner.slots.clone().try_acquire_owned().map_err(|_| {
            self.inner.stats.rejected.fetch_add(1, Ordering::Relaxed);
            Error::QueueFull
        })?;
        let (reply, answer) = oneshot::channel();
        let (started, begin) = oneshot::channel();
        let qd = deadline.min(Instant::now() + Duration::from_millis(100));
        let job = Job {
            request,
            reply,
            started,
            cancel: flag,
            deadline,
            queue_deadline: qd,
            _slot: slot,
        };
        self.inner
            .senders
            .get(worker)
            .ok_or(Error::Internal)?
            .try_send(job)
            .map_err(|_| Error::QueueFull)?;
        tokio::time::timeout_at(qd.into(), begin)
            .await?
            .map_err(|_| Error::Closed)?;
        let result = tokio::time::timeout_at(deadline.into(), answer)
            .await?
            .map_err(|_| Error::Closed)??;
        guard.armed = false;
        Ok(result)
    }
    pub(crate) async fn generate(&self, deadline: Instant) -> Result<(Box<[u8; 808]>, KemLease)> {
        let slot = self
            .inner
            .key_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::QueueFull)?;
        let worker = self.inner.next.fetch_add(1, Ordering::Relaxed) % self.inner.senders.len();
        let cancel = Arc::new(AtomicBool::new(false));
        match self
            .run(worker, Request::Generate(slot), cancel.clone(), deadline)
            .await?
        {
            Response::Generated(id, pk) => Ok((
                pk,
                KemLease {
                    inner: self.inner.clone(),
                    worker,
                    id,
                    cancel,
                },
            )),
            _ => Err(Error::Internal),
        }
    }
    pub(crate) async fn encapsulate(
        &self,
        pk: Box<[u8; 808]>,
        deadline: Instant,
    ) -> Result<(Box<[u8; 1160]>, Secret<32>)> {
        let worker = self.inner.next.fetch_add(1, Ordering::Relaxed) % self.inner.senders.len();
        match self
            .run(
                worker,
                Request::Encaps(pk),
                Arc::new(AtomicBool::new(false)),
                deadline,
            )
            .await?
        {
            Response::Encapsulated(ct, ss) => Ok((ct, ss)),
            _ => Err(Error::Internal),
        }
    }
    pub(crate) async fn decapsulate(
        &self,
        lease: KemLease,
        ct: Box<[u8; 1160]>,
        deadline: Instant,
    ) -> Result<Secret<32>> {
        if !Arc::ptr_eq(&lease.inner, &self.inner) {
            return Err(Error::Input);
        }
        match self
            .run(
                lease.worker,
                Request::Decaps(lease.id, ct),
                lease.cancel.clone(),
                deadline,
            )
            .await?
        {
            Response::Decapsulated(ss) => Ok(ss),
            _ => Err(Error::Internal),
        }
    }
    pub fn metrics(&self) -> Metrics {
        Metrics {
            live_keys: self.inner.stats.live.load(Ordering::Acquire),
            executed: self.inner.stats.executed.load(Ordering::Relaxed),
            rejected: self.inner.stats.rejected.load(Ordering::Relaxed),
        }
    }
    pub async fn shutdown(&self) -> Result<()> {
        self.inner.stop.store(true, Ordering::Release);
        let handles = std::mem::take(&mut *self.inner.threads.lock().map_err(|_| Error::Internal)?);
        tokio::task::spawn_blocking(move || {
            for h in handles {
                h.join().map_err(|_| Error::Internal)?;
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::Internal)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn clean(pool: &KemPool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while pool.metrics().live_keys != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn worker_roundtrip_and_drop_lease() {
        let p = KemPool::new(2).unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        for _ in 0..32 {
            let (pk, key) = p.generate(end).await.unwrap();
            let (ct, a) = p.encapsulate(pk, end).await.unwrap();
            let b = p.decapsulate(key, ct, end).await.unwrap();
            assert_eq!(a.bytes(), b.bytes());
        }
        let (_, key) = p.generate(end).await.unwrap();
        assert_eq!(p.metrics().live_keys, 1);
        drop(key);
        clean(&p).await;
        p.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn malformed_ct_consumes_native_key() {
        let p = KemPool::new(1).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        let (_, key) = p.generate(end).await.unwrap();
        assert!(matches!(
            p.decapsulate(key, Box::new([0; 1160]), end).await,
            Err(Error::Input)
        ));
        clean(&p).await;
        p.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn expiration_cleans_abandoned_key() {
        let p = KemPool::new(1).unwrap();
        let (_, key) = p
            .generate(Instant::now() + Duration::from_millis(100))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        clean(&p).await;
        drop(key);
        p.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn queue_full_and_cancel_does_not_free_running_state() {
        let p = KemPool::with_capacity(1, 1).unwrap();
        let q = p.clone();
        let end = Instant::now() + Duration::from_secs(2);
        let task = tokio::spawn(async move {
            q.run(
                0,
                Request::Hold(Duration::from_millis(150)),
                Arc::new(AtomicBool::new(false)),
                end,
            )
            .await
            .is_ok()
        });
        while p.metrics().executed == 0 {
            tokio::task::yield_now().await;
        }
        assert!(matches!(p.generate(end).await, Err(Error::QueueFull)));
        task.abort();
        tokio::time::sleep(Duration::from_millis(170)).await;
        let (_, key) = p.generate(end).await.unwrap();
        drop(key);
        clean(&p).await;
        p.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn canceled_generation_cannot_leak_stored_key() {
        let p = KemPool::new(1).unwrap();
        let q = p.clone();
        let task =
            tokio::spawn(async move { q.generate(Instant::now() + Duration::from_secs(1)).await });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        clean(&p).await;
        p.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn queued_deadline_and_canceled_lease_cleanup() {
        let p = KemPool::with_capacity(1, 2).unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        let (_, key) = p.generate(end).await.unwrap();
        let q = p.clone();
        let executed = p.metrics().executed;
        let task = tokio::spawn(async move {
            q.run(
                0,
                Request::Hold(Duration::from_millis(220)),
                Arc::new(AtomicBool::new(false)),
                end,
            )
            .await
            .is_ok()
        });
        while p.metrics().executed == executed {
            tokio::task::yield_now().await;
        }
        drop(key);
        assert!(matches!(p.generate(end).await, Err(Error::Deadline)));
        let _ = task.await;
        clean(&p).await;
        let (_, key) = p.generate(end).await.unwrap();
        drop(key);
        clean(&p).await;
        p.shutdown().await.unwrap();
    }
}
