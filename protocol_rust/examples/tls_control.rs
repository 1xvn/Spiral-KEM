//! TLS-only diagnostic control. No Spiral framing, KEM, worker or secret buffer.
#![forbid(unsafe_code)]
use std::{path::Path, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 4 {
        return Err("cert key cipher(default|aes128|aes256|chacha)".into());
    }
    let mut config =
        (*spiral_protocol::transport::server_config(Path::new(&a[1]), Path::new(&a[2]))?).clone();
    if a[3] != "default" {
        let mut provider = rustls::crypto::ring::default_provider();
        use rustls::crypto::ring::cipher_suite::*;
        provider.cipher_suites = vec![match a[3].as_str() {
            "chacha" => TLS13_CHACHA20_POLY1305_SHA256,
            "aes128" => TLS13_AES_128_GCM_SHA256,
            "aes256" => TLS13_AES_256_GCM_SHA384,
            _ => return Err("unsupported diagnostic cipher".into()),
        }];
        let certs =
            rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(&a[1])?))
                .collect::<std::result::Result<Vec<_>, _>>()?;
        let key =
            rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(&a[2])?))?
                .ok_or("key")?;
        config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        config.alpn_protocols = vec![spiral_protocol::transport::ALPN.to_vec()];
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.send_half_rtt_data = false;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    println!("{}", listener.local_addr()?.port());
    let (sock, _) = listener.accept().await?;
    let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
        .accept(sock)
        .await?;
    println!("{:?}", tls.get_ref().1.negotiated_cipher_suite());
    let mut data = [0u8; 120];
    tls.read_exact(&mut data).await?;
    tls.write_all(&data).await?;
    tls.flush().await?;
    tls.shutdown().await?;
    let mut byte = [0; 1];
    if tls.read(&mut byte).await? != 0 {
        return Err("trailing data".into());
    }
    Ok(())
}
