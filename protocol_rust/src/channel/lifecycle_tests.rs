//! Compound channel-loop regressions with controlled synthetic I/O.
//! These tests do not stand in for authenticated TLS integration tests.
use super::*;
use crate::{
    secret::Secret,
    wire::{Header, HEADER},
};
use std::{
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::{io::ReadBuf, sync::Notify};

fn life() -> Arc<Life> {
    let now = Instant::now();
    let (change, _) = watch::channel(0);
    Arc::new(Life {
        state: AtomicU8::new(OPEN),
        reason: AtomicU8::new(0),
        started: now,
        last: Mutex::new(now),
        closing: Mutex::new(None),
        write_done: AtomicBool::new(false),
        read_done: AtomicBool::new(false),
        change,
        _lease: Mutex::new(None),
        _id: Mutex::new(None),
    })
}
fn plain(pool: &Arc<Pool>, value: &[u8]) -> Plaintext {
    let mut buffer = pool.take().unwrap();
    buffer.data.extend_from_slice(value);
    Plaintext {
        buffer,
        start: 0,
        length: value.len(),
    }
}
fn tx() -> Tx {
    Tx::new(Secret::zeros(), [0; 4], [1; 16], 0).unwrap()
}
fn rx() -> Rx {
    Rx::new(Secret::zeros(), [0; 4], [1; 16], 1).unwrap()
}
fn command(pool: &Arc<Pool>, value: &[u8]) -> (SendRequest, oneshot::Receiver<Result<()>>) {
    let (ack, result) = oneshot::channel();
    (
        SendRequest {
            plaintext: plain(pool, value),
            ack,
            deadline: Instant::now() + Duration::from_secs(5),
        },
        result,
    )
}
fn emitted(id: &str, subcases: usize) {
    println!(
        "LIFECYCLE_CASE {}",
        serde_json::json!({
            "id": id, "status": "passed", "subcases": subcases,
            "scope": "synthetic_channel_io"
        })
    );
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("lifecycle watchdog expired; timeout is not a passing rejection")
}

#[derive(Clone, Copy)]
enum Shutdown {
    Ready,
    Pending,
    Error,
}
struct WriteState {
    bytes: Vec<u8>,
    released: bool,
    waker: Option<Waker>,
    flushes: usize,
    flushed_bytes: usize,
    shutdown_calls: usize,
    shutdown_after_flush: bool,
}
struct Writer {
    state: Arc<Mutex<WriteState>>,
    blocked: Arc<Notify>,
    shutdown_seen: Arc<Notify>,
    chunk: usize,
    stop: usize,
    shutdown: Shutdown,
}
impl Writer {
    fn new(chunk: usize, stop: usize, shutdown: Shutdown) -> Self {
        Self {
            state: Arc::new(Mutex::new(WriteState {
                bytes: Vec::new(),
                released: false,
                waker: None,
                flushes: 0,
                flushed_bytes: 0,
                shutdown_calls: 0,
                shutdown_after_flush: false,
            })),
            blocked: Arc::new(Notify::new()),
            shutdown_seen: Arc::new(Notify::new()),
            chunk,
            stop,
            shutdown,
        }
    }
}
fn release_writer(state: &Arc<Mutex<WriteState>>) {
    let wake = {
        let mut s = state.lock().unwrap();
        s.released = true;
        s.waker.take()
    };
    if let Some(waker) = wake {
        waker.wake();
    }
}
impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut s = self.state.lock().unwrap();
        if !s.released && s.bytes.len() >= self.stop {
            s.waker = Some(cx.waker().clone());
            self.blocked.notify_one();
            return Poll::Pending;
        }
        let limit = if s.released {
            usize::MAX
        } else {
            self.stop - s.bytes.len()
        };
        let n = bytes.len().min(self.chunk).min(limit);
        s.bytes.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut state = self.state.lock().unwrap();
        state.flushes += 1;
        state.flushed_bytes = state.bytes.len();
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut s = self.state.lock().unwrap();
        s.shutdown_calls += 1;
        s.shutdown_after_flush = s.flushes > 0;
        assert!(s.shutdown_after_flush, "shutdown preceded record flush");
        assert_eq!(
            s.flushed_bytes,
            s.bytes.len(),
            "shutdown preceded final flush"
        );
        let mut at = 0;
        let mut last_kind = None;
        while at < s.bytes.len() {
            assert!(
                s.bytes.len() - at >= HEADER,
                "shutdown after partial header"
            );
            let header = Header::parse(&s.bytes[at..at + HEADER]).unwrap();
            at += HEADER + header.length;
            assert!(at <= s.bytes.len(), "shutdown after partial body");
            last_kind = Some(header.kind);
        }
        assert_eq!(last_kind, Some(CLOSE), "shutdown before complete CLOSE");
        self.shutdown_seen.notify_one();
        match self.shutdown {
            Shutdown::Ready => Poll::Ready(Ok(())),
            Shutdown::Pending => Poll::Pending,
            Shutdown::Error => Poll::Ready(Err(std::io::Error::other("injected shutdown error"))),
        }
    }
}

fn verify_frames(raw: &[u8], expected: &[(u8, &[u8])]) {
    let pool = Pool::new();
    let mut receiver = rx();
    let mut at = 0;
    for (sequence, &(kind, plaintext)) in expected.iter().enumerate() {
        assert!(raw.len() >= at + HEADER, "missing complete frame header");
        let h = Header::parse(&raw[at..at + HEADER]).unwrap();
        assert_eq!(h.sequence, sequence as u64);
        let end = at + HEADER + h.length;
        assert!(end <= raw.len(), "truncated committed frame");
        let mut buffer = pool.take().unwrap();
        buffer.data.extend_from_slice(&raw[at..end]);
        let (actual_kind, actual_plain) = receiver.decode(buffer).unwrap();
        assert_eq!(actual_kind, kind);
        assert_eq!(actual_plain.as_bytes(), plaintext);
        at = end;
    }
    assert_eq!(
        at,
        raw.len(),
        "duplicate, retried, or unexpected trailing frame"
    );
    assert_eq!(
        receiver.closed,
        expected.last().is_some_and(|x| x.0 == CLOSE)
    );
}

#[tokio::test]
async fn cancelled_queued_ack_keeps_complete_record() {
    for chunk in [1, 7, 31] {
        let owner = life();
        let pool = Pool::new();
        let writer = Writer::new(chunk, usize::MAX, Shutdown::Ready);
        let observed = writer.state.clone();
        let (send, commands) = mpsc::channel(8);
        let (request, ack) = command(&pool, b"queued then cancelled");
        send.send(request).await.ok().unwrap();
        drop(ack);
        drop(send);
        bounded(write_loop(writer, tx(), commands, owner))
            .await
            .unwrap();
        let state = observed.lock().unwrap();
        verify_frames(
            &state.bytes,
            &[(DATA, b"queued then cancelled"), (CLOSE, &[0])],
        );
        assert_eq!(state.shutdown_calls, 1);
        assert_eq!(state.flushes, 2);
    }
    emitted("cancelled_queued_ack_keeps_complete_record", 3);
}

#[tokio::test]
async fn cancelled_sender_during_partial_write_keeps_commit() {
    for chunk in [1, 7, 31] {
        let owner = life();
        let pool = Pool::new();
        let writer = Writer::new(chunk, 13, Shutdown::Ready);
        let blocked = writer.blocked.clone();
        let observed = writer.state.clone();
        let (send, commands) = mpsc::channel(8);
        let sender = Sender {
            tx: send,
            life: owner.clone(),
            pool,
        };
        let app = tokio::spawn(async move { sender.send(b"in flight cancellation").await });
        let session = owner.clone();
        let task = tokio::spawn(async move { write_loop(writer, tx(), commands, session).await });
        bounded(blocked.notified()).await;
        assert_eq!(observed.lock().unwrap().bytes.len(), 13);
        app.abort();
        assert!(bounded(app).await.unwrap_err().is_cancelled());
        owner.active();
        owner.close(0);
        release_writer(&observed);
        bounded(task).await.unwrap().unwrap();
        let state = observed.lock().unwrap();
        verify_frames(
            &state.bytes,
            &[(DATA, b"in flight cancellation"), (CLOSE, &[0])],
        );
        assert_eq!(state.shutdown_calls, 1);
        assert_eq!(state.flushes, 2);
    }
    emitted("cancelled_sender_during_partial_write_keeps_commit", 3);
}

#[tokio::test]
async fn close_racing_partial_write_rejects_queued_requests() {
    for chunk in [1, 7, 31] {
        let owner = life();
        let pool = Pool::new();
        let writer = Writer::new(chunk, 17, Shutdown::Ready);
        let blocked = writer.blocked.clone();
        let observed = writer.state.clone();
        let (send, commands) = mpsc::channel(8);
        let (first, ack) = command(&pool, b"committed first");
        send.send(first).await.ok().unwrap();
        let session = owner.clone();
        let task = tokio::spawn(async move { write_loop(writer, tx(), commands, session).await });
        bounded(blocked.notified()).await;
        let mut queued = Vec::new();
        for _ in 0..3 {
            let (request, ack) = command(&pool, b"must not be sent");
            send.send(request).await.ok().unwrap();
            queued.push(ack);
        }
        owner.active();
        owner.close(0);
        owner.close(2);
        release_writer(&observed);
        bounded(task).await.unwrap().unwrap();
        assert_eq!(bounded(ack).await.unwrap(), Ok(()));
        for ack in queued {
            assert_eq!(bounded(ack).await.unwrap(), Err(Error::Closed));
        }
        assert!(send.is_closed());
        let state = observed.lock().unwrap();
        verify_frames(&state.bytes, &[(DATA, b"committed first"), (CLOSE, &[0])]);
        assert_eq!(state.shutdown_calls, 1);
        assert_eq!(state.flushes, 2);
    }
    emitted("close_racing_partial_write_rejects_queued_requests", 3);
}

#[tokio::test]
async fn pending_shutdown_after_flushed_close_expires() {
    for chunk in [1, 7, 31] {
        let owner = life();
        owner.close(0);
        let writer = Writer::new(chunk, usize::MAX, Shutdown::Pending);
        let seen = writer.shutdown_seen.clone();
        let observed = writer.state.clone();
        let (_send, commands) = mpsc::channel(8);
        let session = owner.clone();
        let task = tokio::spawn(async move { write_loop(writer, tx(), commands, session).await });
        bounded(seen.notified()).await;
        *owner.closing.lock().unwrap() = Some(Instant::now() - Duration::from_secs(3));
        owner.active();
        assert_eq!(bounded(task).await.unwrap(), Err(Error::Deadline));
        let state = observed.lock().unwrap();
        verify_frames(&state.bytes, &[(CLOSE, &[0])]);
        assert!(state.shutdown_calls >= 1);
        assert_eq!(state.flushes, 1);
    }
    emitted("pending_shutdown_after_flushed_close_expires", 3);
}

#[tokio::test]
async fn failed_shutdown_after_flushed_close_is_not_clean() {
    for chunk in [1, 7, 31] {
        let owner = life();
        owner.close(0);
        let writer = Writer::new(chunk, usize::MAX, Shutdown::Error);
        let observed = writer.state.clone();
        let (_send, commands) = mpsc::channel(8);
        assert_eq!(
            bounded(write_loop(writer, tx(), commands, owner)).await,
            Err(Error::Transport)
        );
        let state = observed.lock().unwrap();
        verify_frames(&state.bytes, &[(CLOSE, &[0])]);
        assert_eq!(state.shutdown_calls, 1);
        assert_eq!(state.flushes, 1);
    }
    emitted("failed_shutdown_after_flushed_close_is_not_clean", 3);
}

struct ReadState {
    position: usize,
    released: bool,
    waker: Option<Waker>,
}
struct Reader {
    bytes: Vec<u8>,
    chunk: usize,
    stop: usize,
    observed_at: usize,
    state: Arc<Mutex<ReadState>>,
    blocked: Arc<Notify>,
    observed: Arc<Notify>,
}
impl Reader {
    fn new(bytes: Vec<u8>, chunk: usize, stop: usize, observed_at: usize) -> Self {
        Self {
            bytes,
            chunk,
            stop,
            observed_at,
            state: Arc::new(Mutex::new(ReadState {
                position: 0,
                released: false,
                waker: None,
            })),
            blocked: Arc::new(Notify::new()),
            observed: Arc::new(Notify::new()),
        }
    }
}
fn release_reader(state: &Arc<Mutex<ReadState>>) {
    let wake = {
        let mut s = state.lock().unwrap();
        s.released = true;
        s.waker.take()
    };
    if let Some(waker) = wake {
        waker.wake();
    }
}
impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        target: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut s = self.state.lock().unwrap();
        if !s.released && s.position >= self.stop {
            s.waker = Some(cx.waker().clone());
            self.blocked.notify_one();
            return Poll::Pending;
        }
        let limit = if s.released {
            usize::MAX
        } else {
            self.stop - s.position
        };
        let before = s.position;
        let n = target
            .remaining()
            .min(self.chunk)
            .min(self.bytes.len() - s.position)
            .min(limit);
        target.put_slice(&self.bytes[s.position..s.position + n]);
        s.position += n;
        if before < self.observed_at && s.position >= self.observed_at {
            self.observed.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}
fn data_then_close(pool: &Arc<Pool>, value: &[u8], tail: bool) -> (Vec<u8>, usize) {
    let mut sender = tx();
    let data = sender.data(plain(pool, value)).unwrap();
    let boundary = data.data.len();
    let mut bytes = data.data.clone();
    bytes.extend_from_slice(&sender.close(0).unwrap());
    if tail {
        bytes.push(0x53);
    }
    (bytes, boundary)
}

#[tokio::test]
async fn backpressure_close_discards_undelivered_data_and_finishes() {
    for chunk in [1, 7, 31] {
        let owner = life();
        let pool = Pool::new();
        let (bytes, boundary) = data_then_close(&pool, b"blocked incoming data", false);
        let reader = Reader::new(bytes, chunk, usize::MAX, boundary);
        let observed = reader.observed.clone();
        let position = reader.state.clone();
        let (app, mut received) = mpsc::channel(1);
        app.send(plain(&pool, b"already queued"))
            .await
            .ok()
            .unwrap();
        let session = owner.clone();
        let read_pool = pool.clone();
        let task = tokio::spawn(async move {
            read_loop(reader, rx(), app, session, read_pool, 1, [1; 16]).await
        });
        bounded(observed.notified()).await;
        assert_eq!(position.lock().unwrap().position, boundary);
        owner.close(0);
        bounded(task).await.unwrap().unwrap();
        let queued = received.recv().await.unwrap();
        assert_eq!(queued.as_bytes(), b"already queued");
        drop(queued);
        assert!(received.recv().await.is_none());
        let reclaimed: Vec<_> = (0..18).map(|_| pool.take().unwrap()).collect();
        assert!(matches!(pool.take(), Err(Error::QueueFull)));
        drop(reclaimed);
    }
    emitted(
        "backpressure_close_discards_undelivered_data_and_finishes",
        3,
    );
}

#[tokio::test]
async fn backpressure_failure_cancels_delivery_without_reading_more() {
    for chunk in [1, 7, 31] {
        let owner = life();
        let pool = Pool::new();
        let (bytes, boundary) = data_then_close(&pool, b"blocked then failed", false);
        let reader = Reader::new(bytes, chunk, usize::MAX, boundary);
        let observed = reader.observed.clone();
        let position = reader.state.clone();
        let (app, mut received) = mpsc::channel(1);
        app.send(plain(&pool, b"already queued"))
            .await
            .ok()
            .unwrap();
        let session = owner.clone();
        let read_pool = pool.clone();
        let task = tokio::spawn(async move {
            read_loop(reader, rx(), app, session, read_pool, 1, [1; 16]).await
        });
        bounded(observed.notified()).await;
        owner.fail();
        assert_eq!(bounded(task).await.unwrap(), Err(Error::Closed));
        assert_eq!(position.lock().unwrap().position, boundary);
        let queued = received.recv().await.unwrap();
        assert_eq!(queued.as_bytes(), b"already queued");
        drop(queued);
        assert!(received.recv().await.is_none());
        let reclaimed: Vec<_> = (0..18).map(|_| pool.take().unwrap()).collect();
        drop(reclaimed);
    }
    emitted(
        "backpressure_failure_cancels_delivery_without_reading_more",
        3,
    );
}

#[tokio::test]
async fn fragmented_close_preserves_progress_and_rejects_tail() {
    for chunk in [1, 7, 31] {
        for tail in [false, true] {
            let owner = life();
            let pool = Pool::new();
            let (bytes, boundary) = data_then_close(&pool, b"delivered before closing", tail);
            let expected_length = bytes.len();
            let reader = Reader::new(bytes, chunk, boundary + 17, boundary);
            let blocked = reader.blocked.clone();
            let position = reader.state.clone();
            let (app, mut received) = mpsc::channel(8);
            let session = owner.clone();
            let read_pool = pool.clone();
            let task = tokio::spawn(async move {
                read_loop(reader, rx(), app, session, read_pool, 1, [1; 16]).await
            });
            bounded(blocked.notified()).await;
            let delivered = bounded(received.recv()).await.unwrap();
            assert_eq!(delivered.as_bytes(), b"delivered before closing");
            drop(delivered);
            assert_eq!(position.lock().unwrap().position, boundary + 17);
            owner.active();
            owner.active();
            owner.close(0);
            release_reader(&position);
            let result = bounded(task).await.unwrap();
            assert_eq!(result, if tail { Err(Error::Input) } else { Ok(()) });
            assert_eq!(position.lock().unwrap().position, expected_length);
            assert!(received.recv().await.is_none());
        }
    }
    emitted("fragmented_close_preserves_progress_and_rejects_tail", 6);
}
