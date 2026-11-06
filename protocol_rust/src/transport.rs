#![forbid(unsafe_code)]
use crate::{
    buffer::{Buffer, Pool},
    wire::{self, Header, CLOSE, DATA, HEADER},
    Error, Result,
};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore, ServerConfig};
use std::{
    fs::File,
    io::BufReader,
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
pub const EXPORTER: &[u8] = b"EXPORTER-SpiralOPT2-v0.1";

pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key =
        rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?))?.ok_or(Error::Input)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Crypto)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| Error::Input)?;
    c.alpn_protocols = vec![ALPN.to_vec()];
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
    pub(crate) io: TlsStream<TcpStream>,
    binding: [u8; 32],
    name: String,
    deadline: Instant,
}
impl Transport {
    pub async fn connect(stream: TcpStream, config: Arc<ClientConfig>, name: &str) -> Result<Self> {
        stream.set_nodelay(true)?;
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
        Self::complete(stream.into(), name)
    }
    pub async fn accept(stream: TcpStream, config: Arc<ServerConfig>, name: &str) -> Result<Self> {
        stream.set_nodelay(true)?;
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            TlsAcceptor::from(config).accept(stream),
        )
        .await?
        .map_err(|_| Error::Authentication)?;
        if stream.get_ref().1.server_name() != Some(name) {
            return Err(Error::Authentication);
        }
        Self::complete(stream.into(), name)
    }
    fn complete(mut io: TlsStream<TcpStream>, name: &str) -> Result<Self> {
        let (_, session) = io.get_ref();
        if session.is_handshaking()
            || session.handshake_kind().is_none()
            || session.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || session.alpn_protocol() != Some(ALPN)
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
