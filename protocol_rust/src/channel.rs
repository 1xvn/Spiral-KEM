#![forbid(unsafe_code)]
use crate::{
    admission,
    buffer::Pool,
    handshake::SessionId,
    records::{Rx, Tx},
    schedule::SessionKeys,
    secret::Plaintext,
    transport::{self, Transport},
    wire::{CLOSE, DATA, MAX_DATA},
    Error, Result,
};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

const OPEN: u8 = 0;
const CLOSING: u8 = 1;
const FAILED: u8 = 2;
const CLOSED: u8 = 3;
struct Life {
    state: AtomicU8,
    reason: AtomicU8,
    started: Instant,
    last: Mutex<Instant>,
    closing: Mutex<Option<Instant>>,
    write_done: AtomicBool,
    read_done: AtomicBool,
    change: watch::Sender<u64>,
    _lease: Mutex<Option<admission::Lease>>,
    _id: Mutex<Option<SessionId>>,
}
impl Life {
    fn signal(&self) {
        self.change.send_modify(|v| *v = v.wrapping_add(1));
    }
    fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }
    fn deadline(&self) -> Result<Instant> {
        if self.state() == FAILED {
            return Err(Error::Closed);
        }
        if let Some(t) = *self.closing.lock().map_err(|_| Error::Internal)? {
            return Ok(t + Duration::from_secs(2));
        }
        Ok((self.started + Duration::from_secs(600))
            .min(*self.last.lock().map_err(|_| Error::Internal)? + Duration::from_secs(60)))
    }
    fn active(&self) {
        if let Ok(mut last) = self.last.lock() {
            *last = Instant::now();
        }
        self.signal();
    }
    fn close(&self, reason: u8) {
        if self
            .state
            .compare_exchange(OPEN, CLOSING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.reason.store(reason, Ordering::Release);
            if let Ok(mut t) = self.closing.lock() {
                *t = Some(Instant::now());
            }
        }
        self.signal();
    }
    fn fail(&self) {
        if self.state() != CLOSED {
            self.state.store(FAILED, Ordering::Release);
        }
        self.signal();
    }
    fn done(&self, write: bool) {
        if write {
            self.write_done.store(true, Ordering::Release);
        } else {
            self.read_done.store(true, Ordering::Release);
        }
        if self.write_done.load(Ordering::Acquire) && self.read_done.load(Ordering::Acquire) {
            let _ =
                self.state
                    .compare_exchange(CLOSING, CLOSED, Ordering::AcqRel, Ordering::Acquire);
            if let Ok(mut l) = self._lease.lock() {
                l.take();
            }
            if let Ok(mut id) = self._id.lock() {
                id.take();
            }
        }
        self.signal();
    }
}
struct SendRequest {
    plaintext: Plaintext,
    ack: oneshot::Sender<Result<()>>,
    deadline: Instant,
}
#[derive(Clone)]
pub struct Sender {
    tx: mpsc::Sender<SendRequest>,
    life: Arc<Life>,
    pool: Arc<Pool>,
}
impl Sender {
    pub async fn send(&self, value: &[u8]) -> Result<()> {
        let result = self.send_inner(value).await;
        if matches!(result, Err(Error::Deadline)) {
            self.life.fail();
        }
        result
    }
    async fn send_inner(&self, value: &[u8]) -> Result<()> {
        if value.is_empty() || value.len() > MAX_DATA {
            return Err(Error::Input);
        }
        if self.life.state() != OPEN {
            return Err(Error::Closed);
        }
        // Reserve queue capacity before allocating/copying the caller's plaintext.
        let deadline = self.life.deadline()?;
        let slot = tokio::time::timeout_at(deadline.into(), self.tx.reserve())
            .await?
            .map_err(|_| Error::Closed)?;
        if self.life.state() != OPEN {
            return Err(Error::Closed);
        }
        let mut change = self.life.change.subscribe();
        let future = self.pool.acquire();
        tokio::pin!(future);
        let mut buffer = loop {
            if self.life.state() != OPEN {
                return Err(Error::Closed);
            }
            tokio::select! {biased;_=change.changed()=>{},r=&mut future=>break r?,_=tokio::time::sleep_until(deadline.into())=>return Err(Error::Deadline)}
        };
        buffer.data.extend_from_slice(value);
        let (tx, rx) = oneshot::channel();
        slot.send(SendRequest {
            plaintext: Plaintext {
                buffer,
                start: 0,
                length: value.len(),
            },
            ack: tx,
            deadline,
        });
        tokio::time::timeout_at(deadline.into(), rx)
            .await?
            .map_err(|_| Error::Closed)?
    }
}
pub struct Session {
    sender: Sender,
    rx: mpsc::Receiver<Plaintext>,
    life: Arc<Life>,
    tasks: Vec<JoinHandle<()>>,
}
impl Session {
    pub(crate) fn start(
        io: Transport,
        keys: SessionKeys,
        role: u8,
        lease: Option<admission::Lease>,
        id: Option<SessionId>,
    ) -> Result<Self> {
        let SessionKeys {
            sid,
            c,
            s,
            cp,
            sp,
            transcript: _,
        } = keys;
        let (tx_key, rx_key, tp, rp) = if role == 0 {
            (c, s, cp, sp)
        } else if role == 1 {
            (s, c, sp, cp)
        } else {
            return Err(Error::Input);
        };
        let tx = Tx::new(tx_key, tp, sid, role)?;
        let rx = Rx::new(rx_key, rp, sid, role)?;
        let now = Instant::now();
        let (change, _) = watch::channel(0);
        let life = Arc::new(Life {
            state: AtomicU8::new(OPEN),
            reason: AtomicU8::new(0),
            started: now,
            last: Mutex::new(now),
            closing: Mutex::new(None),
            write_done: AtomicBool::new(false),
            read_done: AtomicBool::new(false),
            change,
            _lease: Mutex::new(lease),
            _id: Mutex::new(id),
        });
        let pool = Pool::new();
        let (send, commands) = mpsc::channel(8);
        let (received, receive) = mpsc::channel(8);
        let (read, write) = tokio::io::split(io.io);
        let a = life.clone();
        let writer = tokio::spawn(async move {
            let result = write_loop(write, tx, commands, a.clone()).await;
            if result.is_err() {
                a.fail();
            }
            a.done(true);
        });
        let a = life.clone();
        let b = pool.clone();
        let reader = tokio::spawn(async move {
            let result = read_loop(read, rx, received, a.clone(), b, role, sid).await;
            if result.is_err() {
                a.fail();
            }
            a.done(false);
        });
        Ok(Self {
            sender: Sender {
                tx: send,
                life: life.clone(),
                pool,
            },
            rx: receive,
            life,
            tasks: vec![writer, reader],
        })
    }
    pub fn sender(&self) -> Sender {
        self.sender.clone()
    }
    pub async fn send(&self, value: &[u8]) -> Result<()> {
        self.sender.send(value).await
    }
    pub async fn receive(&mut self) -> Result<Plaintext> {
        let mut change = self.life.change.subscribe();
        loop {
            if self.life.state() == FAILED {
                return Err(Error::Closed);
            }
            // A clean peer CLOSE may finish on the I/O tasks before the app is
            // scheduled. Previously authenticated queued DATA remains readable.
            if let Ok(p) = self.rx.try_recv() {
                return Ok(p);
            }
            if self.life.state() == CLOSED {
                return Err(Error::Closed);
            }
            tokio::select! {biased;
                _=change.changed()=>{},
                v=self.rx.recv()=>{let p=v.ok_or(Error::Closed)?;if self.life.state()==FAILED{return Err(Error::Closed);}return Ok(p);},
                _=tokio::time::sleep_until(self.life.deadline()?.into())=>{self.life.close(1);return Err(Error::Deadline);}
            }
        }
    }
    pub async fn close(&mut self) -> Result<()> {
        self.life.close(0);
        while let Ok(p) = self.rx.try_recv() {
            drop(p);
        }
        let mut change = self.life.change.subscribe();
        loop {
            match self.life.state() {
                CLOSED => break,
                FAILED => return Err(Error::Closed),
                _ => {}
            }
            tokio::select! {_=change.changed()=>{},_=tokio::time::sleep_until(self.life.deadline()?.into())=>{self.life.fail();return Err(Error::Deadline);}}
        }
        for task in self.tasks.drain(..) {
            task.await.map_err(|_| Error::Internal)?;
        }
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if self.life.state() != CLOSED {
            self.life.fail();
        }
    }
}

async fn write_one<W: AsyncWrite + Unpin, B: AsRef<[u8]> + Send>(
    io: &mut W,
    buf: B,
    life: &Arc<Life>,
    deadline: Instant,
) -> Result<()> {
    let mut change = life.change.subscribe();
    // Keep the same pending frame and future across activity notifications.
    let future = transport::write_record(io, buf.as_ref());
    tokio::pin!(future);
    loop {
        if life.state() == FAILED {
            return Err(Error::Closed);
        }
        tokio::select! {biased;
            _=change.changed()=>{},
            r=&mut future=>{r?;life.active();return Ok(());},
            _=tokio::time::sleep_until(deadline.min(life.deadline()?).into())=>return Err(Error::Deadline)
        }
    }
}
async fn write_loop<W: AsyncWrite + Unpin>(
    mut io: W,
    mut tx: Tx,
    mut commands: mpsc::Receiver<SendRequest>,
    life: Arc<Life>,
) -> Result<()> {
    let mut change = life.change.subscribe();
    let mut batch = 0;
    loop {
        match life.state() {
            FAILED => return Err(Error::Closed),
            CLOSING => break,
            CLOSED => return Ok(()),
            _ => {}
        }
        tokio::select! {biased;
            _=change.changed()=>continue,
            _=tokio::time::sleep_until(life.deadline()?.into())=>{life.close(1);continue;},
            cmd=commands.recv()=>{
                let Some(cmd)=cmd else{life.close(0);continue;};
                if life.state()!=OPEN{let _=cmd.ack.send(Err(Error::Closed));continue;}
                let result=if Instant::now()>=cmd.deadline{Err(Error::Deadline)}else{match tx.data(cmd.plaintext){
                    Ok(raw)=>write_one(&mut io,raw,&life,cmd.deadline).await,
                    Err(Error::Limit(reason))=>{life.close(reason);Err(Error::Limit(reason))},
                    Err(e)=>Err(e)
                }};
                let failed=result.is_err()&&!matches!(result,Err(Error::Limit(_)));let _=cmd.ack.send(result);if failed{return Err(Error::Transport);}
                batch+=1;if batch==4{tokio::task::yield_now().await;batch=0;}
            }
        }
    }
    commands.close();
    while let Ok(cmd) = commands.try_recv() {
        let _ = cmd.ack.send(Err(Error::Closed));
    }
    let reason = life.reason.load(Ordering::Acquire);
    let raw = tx.close(reason)?;
    write_one(&mut io, raw, &life, life.deadline()?).await?;
    // Spiral CLOSE is already authenticated and flushed before TLS close_notify.
    let mut change = life.change.subscribe();
    let future = io.shutdown();
    tokio::pin!(future);
    loop {
        if life.state() == FAILED {
            return Err(Error::Closed);
        }
        tokio::select! {r=&mut future=>{r?;return Ok(());},_=change.changed()=>{},_=tokio::time::sleep_until(life.deadline()?.into())=>return Err(Error::Deadline)}
    }
}

async fn read_loop<R: AsyncRead + Unpin>(
    mut io: R,
    mut rx: Rx,
    app: mpsc::Sender<Plaintext>,
    life: Arc<Life>,
    pool: Arc<Pool>,
    role: u8,
    sid: [u8; 16],
) -> Result<()> {
    let mut change = life.change.subscribe();
    let mut batch = 0;
    loop {
        if life.state() == FAILED {
            return Err(Error::Closed);
        }
        // One persistent read future owns partial header/body progress. Only a
        // terminal timeout/failure cancels it; the session is then discarded.
        let raw = {
            let mut operation_deadline = life.deadline()?;
            let future =
                transport::read_record(&mut io, &pool, 1 - role, sid, rx.expected_sequence());
            tokio::pin!(future);
            loop {
                if life.state() == FAILED {
                    return Err(Error::Closed);
                }
                tokio::select! {biased;
                    _=change.changed()=>{},
                    r=&mut future=>break r?,
                    _=tokio::time::sleep_until(operation_deadline.min(life.deadline()?).into())=>{
                        if life.state()==OPEN{life.close(1);operation_deadline=life.deadline()?;}else{return Err(Error::Deadline);}
                    }
                }
            }
        };
        let (kind, p) = rx.decode(raw)?;
        life.active();
        if kind == CLOSE {
            drop(p);
            life.close(0);
            // Require the TLS authenticated end, and reject any trailing protocol bytes.
            let mut byte = [0; 1];
            let future = io.read(&mut byte);
            tokio::pin!(future);
            loop {
                if life.state() == FAILED {
                    return Err(Error::Closed);
                }
                tokio::select! {r=&mut future=>{if r?!=0{return Err(Error::Input);}return Ok(());},_=change.changed()=>{},_=tokio::time::sleep_until(life.deadline()?.into())=>return Err(Error::Deadline)}
            }
        }
        if kind != DATA {
            return Err(Error::Input);
        }
        if life.state() == OPEN {
            let delivery_deadline = life.deadline()?;
            let future = app.send(p);
            tokio::pin!(future);
            loop {
                if life.state() != OPEN {
                    break;
                }
                tokio::select! {r=&mut future=>{r.map_err(|_|Error::Closed)?;break;},_=change.changed()=>{},_=tokio::time::sleep_until(delivery_deadline.min(life.deadline()?).into())=>{life.close(1);break;}}
            }
        }
        batch += 1;
        if batch == 4 {
            tokio::task::yield_now().await;
            batch = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
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
    #[tokio::test]
    async fn authenticated_queued_data_survives_clean_close() {
        let life = life();
        let pool = Pool::new();
        let (tx, rx) = mpsc::channel(8);
        tx.send(plain(&pool, b"last response")).await.ok().unwrap();
        drop(tx);
        let (send, _) = mpsc::channel(8);
        life.state.store(CLOSED, Ordering::Release);
        let mut s = Session {
            sender: Sender {
                tx: send,
                life: life.clone(),
                pool,
            },
            rx,
            life,
            tasks: Vec::new(),
        };
        assert_eq!(s.receive().await.unwrap().as_bytes(), b"last response");
        assert!(s.receive().await.is_err());
    }
    #[tokio::test]
    async fn partial_write_deadline_cannot_be_extended_by_activity() {
        let life = life();
        let pool = Pool::new();
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let mut b = pool.take().unwrap();
        b.data.resize(128, b'S');
        let activity = life.clone();
        let ticker = tokio::spawn(async move {
            for _ in 0..40 {
                activity.active();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        let end = Instant::now() + Duration::from_millis(25);
        assert!(matches!(
            write_one(&mut writer, b, &life, end).await,
            Err(Error::Deadline)
        ));
        drop(writer);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"S");
        ticker.abort();
        let _ = ticker.await;
    }
    #[tokio::test]
    async fn partial_reads_keep_progress_across_notifications() {
        let life = life();
        let pool = Pool::new();
        let (mut writer, reader) = tokio::io::duplex(128);
        let (tx, mut app) = mpsc::channel(8);
        let mut enc = Tx::new(Secret::zeros(), [0; 4], [1; 16], 0).unwrap();
        let raw = enc.data(plain(&pool, b"fragmented message")).unwrap();
        let rx = Rx::new(Secret::zeros(), [0; 4], [1; 16], 1).unwrap();
        let l = life.clone();
        let p = pool.clone();
        let task = tokio::spawn(async move { read_loop(reader, rx, tx, l, p, 1, [1; 16]).await });
        for b in &raw.data {
            writer.write_all(&[*b]).await.unwrap();
            life.active();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), app.recv())
                .await
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"fragmented message"
        );
        life.fail();
        drop(writer);
        assert!(task.await.unwrap().is_err());
    }
    #[tokio::test]
    async fn close_and_failure_have_finite_deadlines() {
        let l = life();
        let d = l.deadline().unwrap();
        l.close(0);
        assert!(l.deadline().unwrap() < d);
        let fixed = l.deadline().unwrap();
        l.active();
        l.close(2);
        assert_eq!(l.deadline().unwrap(), fixed);
        l.fail();
        assert!(l.deadline().is_err());
    }

    #[test]
    fn age_idle_and_close_deadlines_remain_independent() {
        let mut owner = life();
        Arc::get_mut(&mut owner).unwrap().started = Instant::now() - Duration::from_secs(601);
        owner.active();
        assert!(owner.deadline().unwrap() < Instant::now());
        let owner = life();
        *owner.last.lock().unwrap() = Instant::now() - Duration::from_secs(61);
        assert!(owner.deadline().unwrap() < Instant::now());
        owner.close(1);
        *owner.closing.lock().unwrap() = Some(Instant::now() - Duration::from_secs(3));
        owner.active();
        assert!(owner.deadline().unwrap() < Instant::now());
    }

    #[tokio::test]
    async fn failed_session_does_not_release_queued_plaintext_to_application() {
        let life = life();
        let pool = Pool::new();
        let (tx, rx) = mpsc::channel(8);
        tx.send(plain(&pool, b"queued authenticated data"))
            .await
            .ok()
            .unwrap();
        drop(tx);
        let (send, _) = mpsc::channel(8);
        let mut session = Session {
            sender: Sender {
                tx: send,
                life: life.clone(),
                pool: pool.clone(),
            },
            rx,
            life: life.clone(),
            tasks: Vec::new(),
        };
        life.fail();
        assert!(matches!(session.receive().await, Err(Error::Closed)));
        let held: Vec<_> = (0..17).map(|_| pool.take().unwrap()).collect();
        assert!(pool.take().is_err());
        drop(session);
        let returned = pool.take().unwrap();
        assert!(returned.data.is_empty());
        drop(returned);
        drop(held);
    }

    #[tokio::test]
    async fn failed_partial_transport_cannot_retry_or_roll_back_nonce() {
        let life = life();
        let pool = Pool::new();
        let (writer, mut peer) = tokio::io::duplex(1);
        let (commands, pending) = mpsc::channel(8);
        let (ack, result) = oneshot::channel();
        commands
            .send(SendRequest {
                plaintext: plain(&pool, b"message"),
                ack,
                deadline: Instant::now() + Duration::from_millis(20),
            })
            .await
            .ok()
            .unwrap();
        let tx = Tx::new(Secret::zeros(), [0; 4], [1; 16], 0).unwrap();
        assert!(matches!(
            write_loop(writer, tx, pending, life.clone()).await,
            Err(Error::Transport)
        ));
        assert!(matches!(result.await.unwrap(), Err(Error::Deadline)));
        assert!(commands.is_closed());
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes.len(), 1);
        // The writer and its Tx owner have gone away; retry cannot access them.
        assert!(commands
            .send(SendRequest {
                plaintext: plain(&pool, b"retry"),
                ack: oneshot::channel().0,
                deadline: Instant::now() + Duration::from_secs(1)
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn authenticated_close_finishes_before_transport_shutdown() {
        struct Writer {
            observed: Arc<Mutex<(Vec<u8>, bool)>>,
            limit: usize,
        }
        impl AsyncWrite for Writer {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                bytes: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                let mut state = self.observed.lock().unwrap();
                let n = bytes.len().min(7).min(self.limit - state.0.len());
                if n == 0 {
                    return std::task::Poll::Pending;
                }
                state.0.extend_from_slice(&bytes[..n]);
                std::task::Poll::Ready(Ok(n))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let mut state = self.observed.lock().unwrap();
                assert_eq!(
                    state.0.len(),
                    57,
                    "shutdown before authenticated CLOSE finished"
                );
                state.1 = true;
                std::task::Poll::Ready(Ok(()))
            }
        }
        for limit in [56, 57] {
            let life = life();
            life.close(0);
            *life.closing.lock().unwrap() = Some(Instant::now() - Duration::from_millis(1970));
            let observed = Arc::new(Mutex::new((Vec::new(), false)));
            let writer = Writer {
                observed: observed.clone(),
                limit,
            };
            let tx = Tx::new(Secret::zeros(), [0; 4], [1; 16], 0).unwrap();
            let (_send, commands) = mpsc::channel(8);
            let result = write_loop(writer, tx, commands, life).await;
            let state = observed.lock().unwrap();
            assert_eq!(state.0.len(), limit);
            assert_eq!(state.1, limit == 57);
            if limit == 57 {
                result.unwrap();
            } else {
                assert!(matches!(result, Err(Error::Deadline)));
            }
        }
    }

    #[tokio::test]
    async fn slow_header_cannot_extend_deadline_or_deliver_after_expiry() {
        let life = life();
        *life.last.lock().unwrap() = Instant::now() - Duration::from_millis(59980);
        let pool = Pool::new();
        let mut tx = Tx::new(Secret::zeros(), [0; 4], [1; 16], 0).unwrap();
        let raw = tx.data(plain(&pool, b"late")).unwrap();
        let rx = Rx::new(Secret::zeros(), [0; 4], [1; 16], 1).unwrap();
        let (mut peer, reader) = tokio::io::duplex(1024);
        let (app, mut received) = mpsc::channel(8);
        let l = life.clone();
        let read_pool = pool.clone();
        let task =
            tokio::spawn(async move { read_loop(reader, rx, app, l, read_pool, 1, [1; 16]).await });
        let activity = life.clone();
        let dribble = tokio::spawn(async move {
            // Let read_loop capture its original absolute deadline first.
            tokio::task::yield_now().await;
            for byte in &raw.data {
                peer.write_all(&[*byte]).await.unwrap();
                activity.active();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            peer
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while life.state() == OPEN {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(life.state(), CLOSING);
        let peer = dribble.await.unwrap();
        assert!(received.try_recv().is_err());
        *life.closing.lock().unwrap() = Some(Instant::now() - Duration::from_secs(3));
        life.signal();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Deadline)
        ));
        assert!(received.try_recv().is_err());
        drop(peer);
    }
}
