#![forbid(unsafe_code)]
use crate::{
    buffer::{Buffer, Pool},
    wire::{self, Header, CLOSE, DATA, HEADER},
    Error, Result,
};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore, ServerConfig};
use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use x509_parser::prelude::*;
pub const ALPN: &[u8] = b"spiral-opt2/0.1";
pub const MTLS_ALPN: &[u8] = b"spiral-opt2/0.1-mtls-lab";
pub const EXPORTER: &[u8] = b"EXPORTER-SpiralOPT2-v0.1";
pub(crate) const MAX_TLS_PEM: usize = 64 * 1024;

#[cfg(feature = "flow-diagnostics")]
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll},
};

/// Observations of the underlying TCP writer, before the TLS layer.
/// Fields may change independently while a snapshot is collected.
#[cfg(feature = "flow-diagnostics")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireSnapshot {
    pub write_pending: bool,
    pub write_pending_polls: u64,
    pub bytes_written: u64,
    pub transport_dropped: bool,
}

#[cfg(feature = "flow-diagnostics")]
#[derive(Default)]
struct WireState {
    write_pending: AtomicBool,
    write_pending_polls: AtomicU64,
    bytes_written: AtomicU64,
    transport_dropped: AtomicBool,
}

/// An observer owns only counters and does not retain the TCP stream.
#[cfg(feature = "flow-diagnostics")]
#[derive(Clone, Default)]
pub struct WireProbe {
    state: Arc<WireState>,
}

#[cfg(feature = "flow-diagnostics")]
impl WireProbe {
    pub fn snapshot(&self) -> WireSnapshot {
        WireSnapshot {
            write_pending: self.state.write_pending.load(Ordering::Acquire),
            write_pending_polls: self.state.write_pending_polls.load(Ordering::Acquire),
            bytes_written: self.state.bytes_written.load(Ordering::Acquire),
            transport_dropped: self.state.transport_dropped.load(Ordering::Acquire),
        }
    }

    fn wrote(&self, result: &Poll<std::io::Result<usize>>) {
        match result {
            Poll::Pending => {
                self.state.write_pending_polls.fetch_add(1, Ordering::AcqRel);
                self.state.write_pending.store(true, Ordering::Release);
            }
            Poll::Ready(Ok(count)) => {
                self.state
                    .bytes_written
                    .fetch_add(*count as u64, Ordering::AcqRel);
                self.state.write_pending.store(false, Ordering::Release);
            }
            Poll::Ready(Err(_)) => {
                self.state.write_pending.store(false, Ordering::Release);
            }
        }
    }
}

/// Delegates I/O without changing socket options, buffers or readiness behavior.
#[cfg(feature = "flow-diagnostics")]
pub(crate) struct ObservedIo<T> {
    inner: Option<T>,
    probe: WireProbe,
}

#[cfg(feature = "flow-diagnostics")]
impl<T> ObservedIo<T> {
    fn new(inner: T) -> Self {
        Self {
            inner: Some(inner),
            probe: WireProbe::default(),
        }
    }

    fn inner_mut(&mut self) -> &mut T {
        self.inner.as_mut().expect("observed stream is owned")
    }
}

#[cfg(feature = "flow-diagnostics")]
impl<T> Drop for ObservedIo<T> {
    fn drop(&mut self) {
        drop(self.inner.take());
        self.probe.state.write_pending.store(false, Ordering::Release);
        self.probe
            .state
            .transport_dropped
            .store(true, Ordering::Release);
    }
}

#[cfg(feature = "flow-diagnostics")]
impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.get_mut().inner_mut()).poll_read(cx, buf)
    }
}

#[cfg(feature = "flow-diagnostics")]
impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(this.inner_mut()).poll_write(cx, buf);
        this.probe.wrote(&result);
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(this.inner_mut()).poll_write_vectored(cx, bufs);
        this.probe.wrote(&result);
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner
            .as_ref()
            .expect("observed stream is owned")
            .is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(this.inner_mut()).poll_flush(cx);
        if matches!(&result, Poll::Ready(Err(_))) {
            this.probe.state.write_pending.store(false, Ordering::Release);
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(this.inner_mut()).poll_shutdown(cx);
        if result.is_ready() {
            this.probe.state.write_pending.store(false, Ordering::Release);
        }
        result
    }
}

#[cfg(feature = "flow-diagnostics")]
type TransportIo = ObservedIo<TcpStream>;
#[cfg(not(feature = "flow-diagnostics"))]
type TransportIo = TcpStream;

/// Parsed DER is erased unless ownership is transferred to the TLS provider.
pub(crate) struct ParsedPrivateKey {
    key: zeroize::Zeroizing<Option<rustls::pki_types::PrivateKeyDer<'static>>>,
}
impl ParsedPrivateKey {
    pub(crate) fn der(&self) -> &rustls::pki_types::PrivateKeyDer<'static> {
        self.key.as_ref().expect("parsed key is owned")
    }
    fn into_der(mut self) -> rustls::pki_types::PrivateKeyDer<'static> {
        self.key.take().expect("parsed key is owned")
    }
}

/// Preserve the loader's policy: one recognized private key, with other PEM
/// items skipped by rustls-pemfile. Both DER owners are erased on rejection.
pub(crate) fn parse_one_private_key(input: &[u8]) -> Result<ParsedPrivateKey> {
    if input.is_empty() || input.len() > MAX_TLS_PEM {
        return Err(Error::Input);
    }
    let mut reader = input;
    let key = ParsedPrivateKey {
        key: zeroize::Zeroizing::new(Some(
            rustls_pemfile::private_key(&mut reader)?.ok_or(Error::Input)?,
        )),
    };
    let second = rustls_pemfile::private_key(&mut reader)?.map(zeroize::Zeroizing::new);
    if second.is_some() {
        return Err(Error::Input);
    }
    Ok(key)
}

/// Read one recognized TLS private-key item through the protected file boundary.
/// The initialized PEM input buffer is erased; parser/provider copies are separate.
pub fn load_tls_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut file = crate::keyfiles::open_private(path)?;
    if file.metadata()?.len() > MAX_TLS_PEM as u64 {
        return Err(Error::Input);
    }
    // Fixed initialized length: reads cannot grow/reallocate this secret buffer.
    let mut input = zeroize::Zeroizing::new(vec![0u8; MAX_TLS_PEM + 1]);
    let mut used = 0;
    while used < input.len() {
        let count = file.read(&mut input[used..])?;
        if count == 0 {
            break;
        }
        used += count;
    }
    if used > MAX_TLS_PEM {
        return Err(Error::Input);
    }
    Ok(parse_one_private_key(&input[..used])?.into_der())
}

pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    build_server_config(cert, key, None)
}

pub fn mtls_server_config(cert: &Path, key: &Path, client_ca: &Path) -> Result<Arc<ServerConfig>> {
    build_server_config(cert, key, Some(client_ca))
}

fn build_server_config(cert: &Path, key: &Path, client_ca: Option<&Path>) -> Result<Arc<ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = load_tls_private_key(key)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Crypto)?;
    let builder = if let Some(ca) = client_ca {
        let mut roots = RootCertStore::empty();
        for der in rustls_pemfile::certs(&mut BufReader::new(File::open(ca)?)) {
            roots.add(der?).map_err(|_| Error::Input)?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .build().map_err(|_| Error::Input)?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut c = builder.with_single_cert(certs, key)
        .map_err(|_| Error::Input)?;
    c.alpn_protocols = vec![if client_ca.is_some() { MTLS_ALPN } else { ALPN }.to_vec()];
    c.send_tls13_tickets = 0;
    c.max_early_data_size = 0;
    c.send_half_rtt_data = false;
    c.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(Arc::new(c))
}
pub fn client_config(ca: &Path) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(ca)?)) {
        roots.add(cert?).map_err(|_| Error::Input)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Crypto)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![ALPN.to_vec()];
    c.resumption = rustls::client::Resumption::disabled();
    c.enable_early_data = false;
    Ok(Arc::new(c))
}

pub struct Transport {
    pub(crate) io: TlsStream<TransportIo>,
    binding: [u8; 32],
    name: String,
    deadline: Instant,
}
impl Transport {
    pub async fn connect(stream: TcpStream, config: Arc<ClientConfig>, name: &str) -> Result<Self> {
        stream.set_nodelay(true)?;
        #[cfg(feature = "flow-diagnostics")]
        let stream = ObservedIo::new(stream);
        let server_name = ServerName::try_from(name.to_owned()).map_err(|_| Error::Input)?;
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            TlsConnector::from(config).connect(server_name, stream),
        )
        .await?
        .map_err(|_| Error::Authentication)?;
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or(Error::Authentication)?;
        let (rest, cert) =
            X509Certificate::from_der(leaf.as_ref()).map_err(|_| Error::Authentication)?;
        let san = cert
            .subject_alternative_name()
            .map_err(|_| Error::Authentication)?
            .ok_or(Error::Authentication)?;
        if !rest.is_empty()
            || !san
                .value
                .general_names
                .iter()
                .any(|n| matches!(n,GeneralName::DNSName(d) if *d==name))
        {
            return Err(Error::Authentication);
        }
        Self::complete(stream.into(), name, ALPN)
    }
    pub async fn accept(stream: TcpStream, config: Arc<ServerConfig>, name: &str) -> Result<Self> {
        Self::accept_profile(stream, config, name, ALPN).await
    }

    pub async fn accept_registered_peer(stream: TcpStream, config: Arc<ServerConfig>, name: &str)
        -> Result<(Self, [u8; 32])>
    {
        let io = Self::accept_profile(stream, config, name, MTLS_ALPN).await?;
        let leaf = io.io.get_ref().1.peer_certificates().and_then(|c| c.first())
            .ok_or(Error::Authentication)?;
        let (_, cert) = X509Certificate::from_der(leaf.as_ref()).map_err(|_| Error::Authentication)?;
        let eku = cert.extended_key_usage().map_err(|_| Error::Authentication)?
            .ok_or(Error::Authentication)?.value;
        if !eku.client_auth || eku.server_auth || eku.any { return Err(Error::Authentication); }
        let fingerprint = crate::schedule::digest(leaf.as_ref());
        Ok((io, fingerprint))
    }

    async fn accept_profile(stream: TcpStream, config: Arc<ServerConfig>, name: &str, alpn: &[u8]) -> Result<Self> {
        stream.set_nodelay(true)?;
        #[cfg(feature = "flow-diagnostics")]
        let stream = ObservedIo::new(stream);
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            TlsAcceptor::from(config).accept(stream),
        )
        .await?
        .map_err(|_| Error::Authentication)?;
        if stream.get_ref().1.server_name() != Some(name) {
            return Err(Error::Authentication);
        }
        Self::complete(stream.into(), name, alpn)
    }
    fn complete(mut io: TlsStream<TransportIo>, name: &str, alpn: &[u8]) -> Result<Self> {
        let (_, session) = io.get_ref();
        if session.is_handshaking()
            || session.handshake_kind().is_none()
            || session.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || session.alpn_protocol() != Some(alpn)
            || session.handshake_kind() == Some(rustls::HandshakeKind::Resumed)
        {
            return Err(Error::Authentication);
        }
        let mut binding = [0; 32];
        match &mut io {
            TlsStream::Client(s) => {
                let c = s.get_mut().1;
                c.set_buffer_limit(Some(64 * 1024));
                c.export_keying_material(&mut binding, EXPORTER, Some(b""))
                    .map_err(|_| Error::Crypto)?;
            }
            TlsStream::Server(s) => {
                let c = s.get_mut().1;
                c.set_buffer_limit(Some(64 * 1024));
                c.export_keying_material(&mut binding, EXPORTER, Some(b""))
                    .map_err(|_| Error::Crypto)?;
            }
        }
        Ok(Self {
            io,
            binding,
            name: name.into(),
            deadline: Instant::now() + Duration::from_secs(10),
        })
    }
    pub fn binding_hash(&self) -> [u8; 32] {
        crate::schedule::digest(&self.binding)
    }
    #[cfg(feature = "flow-diagnostics")]
    pub fn wire_probe(&self) -> WireProbe {
        self.io.get_ref().0.probe.clone()
    }
}

#[async_trait::async_trait]
pub(crate) trait FrameIo: Send {
    fn binding(&self) -> [u8; 32];
    fn name(&self) -> &str;
    fn deadline(&self) -> Instant;
    async fn send(&mut self, raw: &[u8], deadline: Instant) -> Result<()>;
    async fn recv(
        &mut self,
        kind: u8,
        role: u8,
        sid: Option<[u8; 16]>,
        sequence: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>>;
}
#[async_trait::async_trait]
impl FrameIo for Transport {
    fn binding(&self) -> [u8; 32] {
        self.binding
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn deadline(&self) -> Instant {
        self.deadline
    }
    async fn send(&mut self, raw: &[u8], deadline: Instant) -> Result<()> {
        wire::parse(raw)?;
        tokio::time::timeout_at(deadline.into(), async {
            self.io.write_all(raw).await?;
            self.io.flush().await
        })
        .await??;
        Ok(())
    }
    async fn recv(
        &mut self,
        kind: u8,
        role: u8,
        sid: Option<[u8; 16]>,
        sequence: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        tokio::time::timeout_at(deadline.into(), async {
            let mut header = [0; HEADER];
            self.io.read_exact(&mut header).await?;
            let h = Header::parse(&header)?;
            h.expect(Some(kind), role, sid, sequence)?;
            let mut raw = Vec::with_capacity(HEADER + h.length);
            raw.extend_from_slice(&header);
            raw.resize(HEADER + h.length, 0);
            self.io.read_exact(&mut raw[HEADER..]).await?;
            Ok(raw)
        })
        .await?
    }
}
pub(crate) async fn read_record<R: AsyncRead + Unpin>(
    io: &mut R,
    pool: &Arc<Pool>,
    role: u8,
    sid: [u8; 16],
    sequence: u64,
) -> Result<Buffer> {
    let mut header = [0; HEADER];
    io.read_exact(&mut header).await?;
    let h = Header::parse(&header)?;
    h.expect(None, role, Some(sid), sequence)?;
    if !matches!(h.kind, DATA | CLOSE) {
        return Err(Error::Input);
    }
    let mut buf = if h.kind == CLOSE {
        Buffer::close_frame()
    } else {
        pool.acquire().await?
    };
    buf.data.extend_from_slice(&header);
    buf.data.resize(HEADER + h.length, 0);
    io.read_exact(&mut buf.data[HEADER..]).await?;
    Ok(buf)
}

pub(crate) async fn write_record<W: AsyncWrite + Unpin>(io: &mut W, raw: &[u8]) -> Result<()> {
    io.write_all(raw).await?;
    io.flush().await?;
    Ok(())
}

#[cfg(all(test, feature = "flow-diagnostics"))]
mod wire_tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::Mutex,
        task::{Wake, Waker},
    };

    enum Step {
        Pending,
        Written(usize),
        Error,
    }

    struct StubIo {
        steps: VecDeque<Step>,
        calls: Arc<Mutex<Vec<&'static str>>>,
        dropped: Arc<AtomicBool>,
    }

    impl StubIo {
        fn next(&mut self, available: usize) -> Poll<std::io::Result<usize>> {
            match self.steps.pop_front().expect("unexpected write poll") {
                Step::Pending => Poll::Pending,
                Step::Written(count) => {
                    assert!(count <= available);
                    Poll::Ready(Ok(count))
                }
                Step::Error => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            }
        }
    }

    impl Drop for StubIo {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    impl AsyncRead for StubIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.calls.lock().unwrap().push("read");
            buf.put_slice(b"r");
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for StubIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.calls.lock().unwrap().push("write");
            this.next(data.len())
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[std::io::IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.calls.lock().unwrap().push("vectored");
            this.next(data.iter().map(|slice| slice.len()).sum())
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.calls.lock().unwrap().push("flush");
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.calls.lock().unwrap().push("shutdown");
            Poll::Ready(Ok(()))
        }
    }

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    fn fixture(steps: Vec<Step>) -> (ObservedIo<StubIo>, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        let io = StubIo {
            steps: steps.into(),
            calls: Arc::new(Mutex::new(Vec::new())),
            dropped: dropped.clone(),
        };
        (ObservedIo::new(io), dropped)
    }

    #[test]
    fn wire_observer_counts_actual_scalar_and_vectored_write_progress() {
        let (mut io, dropped) = fixture(vec![
            Step::Pending,
            Step::Written(3),
            Step::Pending,
            Step::Written(5),
        ]);
        let probe = io.probe.clone();
        let other_probe = probe.clone();
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        assert!(io.is_write_vectored());
        assert!(Pin::new(&mut io).poll_write(&mut cx, b"abcdef").is_pending());
        assert_eq!(probe.snapshot(), WireSnapshot {
            write_pending: true,
            write_pending_polls: 1,
            bytes_written: 0,
            transport_dropped: false,
        });
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, b"abcdef"),
            Poll::Ready(Ok(3))
        ));
        assert!(!probe.snapshot().write_pending);
        let data = [std::io::IoSlice::new(b"abc"), std::io::IoSlice::new(b"def")];
        assert!(Pin::new(&mut io).poll_write_vectored(&mut cx, &data).is_pending());
        assert!(matches!(
            Pin::new(&mut io).poll_write_vectored(&mut cx, &data),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(probe.snapshot(), WireSnapshot {
            write_pending: false,
            write_pending_polls: 2,
            bytes_written: 8,
            transport_dropped: false,
        });
        assert_eq!(*io.inner.as_ref().unwrap().calls.lock().unwrap(),
                   vec!["write", "write", "vectored", "vectored"]);
        drop(io);
        assert!(dropped.load(Ordering::Acquire));
        assert!(other_probe.snapshot().transport_dropped);
    }

    #[test]
    fn wire_observer_write_error_and_drop_clear_pending_without_inventing_progress() {
        let (mut io, dropped) = fixture(vec![Step::Pending, Step::Error, Step::Pending]);
        let probe = io.probe.clone();
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut io).poll_write(&mut cx, b"data").is_pending());
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, b"data"),
            Poll::Ready(Err(_))
        ));
        assert!(!probe.snapshot().write_pending);
        assert_eq!(probe.snapshot().bytes_written, 0);
        assert!(Pin::new(&mut io).poll_write(&mut cx, b"data").is_pending());
        drop(io);
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(probe.snapshot(), WireSnapshot {
            write_pending: false,
            write_pending_polls: 2,
            bytes_written: 0,
            transport_dropped: true,
        });
    }

    #[test]
    fn wire_observer_delegates_read_flush_and_shutdown() {
        let (mut io, _) = fixture(vec![Step::Pending]);
        let probe = io.probe.clone();
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut io).poll_write(&mut cx, b"data").is_pending());
        assert!(matches!(
            Pin::new(&mut io).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        // A successful TCP flush is not a successful write of pending bytes.
        assert!(probe.snapshot().write_pending);
        let mut bytes = [0; 1];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"r");
        assert!(matches!(
            Pin::new(&mut io).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(*io.inner.as_ref().unwrap().calls.lock().unwrap(),
                   vec!["write", "flush", "read", "shutdown"]);
        assert!(!probe.snapshot().write_pending);
        assert_eq!(probe.snapshot().write_pending_polls, 1);
        assert_eq!(probe.snapshot().bytes_written, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    struct HeaderOnly {
        header: [u8; 40],
        calls: usize,
    }
    impl AsyncRead for HeaderOnly {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let s = self.get_mut();
            s.calls += 1;
            assert_eq!(s.calls, 1, "parser attempted to read an invalid payload");
            buf.put_slice(&s.header);
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn invalid_length_never_reaches_payload_read() {
        let pool = Pool::new();
        for length in [0u32, 16401, 16441, 1 << 20, 0x7fffffff, 0xffffffff] {
            let mut header = Header {
                kind: DATA,
                role: 0,
                sid: [1; 16],
                sequence: 0,
                length: 17,
            }
            .encode()
            .unwrap();
            header[36..40].copy_from_slice(&length.to_be_bytes());
            let mut input = HeaderOnly { header, calls: 0 };
            assert!(read_record(&mut input, &pool, 0, [1; 16], 0).await.is_err());
            assert_eq!(input.calls, 1);
        }
    }
    #[tokio::test]
    async fn close_read_is_not_starved_by_plaintext_buffers() {
        let pool = Pool::new();
        let held: Vec<_> = (0..18).map(|_| pool.take().unwrap()).collect();
        assert!(pool.take().is_err());
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let raw = wire::frame(CLOSE, 0, [1; 16], 0, &[0; 17]).unwrap();
        writer.write_all(&raw).await.unwrap();
        let frame = tokio::time::timeout(
            Duration::from_millis(100),
            read_record(&mut reader, &pool, 0, [1; 16], 0),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(frame.data, raw);
        assert!(pool.take().is_err());
        drop(held);
    }
}
