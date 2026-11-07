#![forbid(unsafe_code)]
use std::{sync::Arc,io::BufReader,fs::File};
use tokio::{net::TcpListener,io::{AsyncReadExt,AsyncWriteExt}};
#[tokio::main(flavor="multi_thread",worker_threads=2)]
async fn main()->Result<(),Box<dyn std::error::Error>> {
 let args:Vec<_>=std::env::args().collect();
 let mut provider=rustls::crypto::ring::default_provider();
 use rustls::crypto::ring::cipher_suite::*;
 provider.cipher_suites=vec![match args[3].as_str(){
  "aes128"=>TLS13_AES_128_GCM_SHA256,"aes256"=>TLS13_AES_256_GCM_SHA384,
  "chacha"=>TLS13_CHACHA20_POLY1305_SHA256,_=>panic!("cipher"),
 }];
 let certs=rustls_pemfile::certs(&mut BufReader::new(File::open(&args[1])?)).collect::<Result<Vec<_>,_>>()?;
 let key=rustls_pemfile::private_key(&mut BufReader::new(File::open(&args[2])?))?.ok_or("key")?;
 let mut config=rustls::ServerConfig::builder_with_provider(Arc::new(provider))
  .with_protocol_versions(&[&rustls::version::TLS13])?.with_no_client_auth().with_single_cert(certs,key)?;
 config.alpn_protocols=vec![b"memory-probe".to_vec()];
 config.send_tls13_tickets=0; config.max_early_data_size=0;config.send_half_rtt_data=false;
 config.session_storage=Arc::new(rustls::server::NoServerSessionStorage{});
 let listener=TcpListener::bind("127.0.0.1:0").await?;
 println!("{}",listener.local_addr()?.port());
 let (socket,_)=listener.accept().await?;
 let mut tls=tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(socket).await?;
 let mut data=[0u8;120];tls.read_exact(&mut data).await?;
 tls.write_all(&data).await?;tls.flush().await?;tls.shutdown().await?;
 let mut byte=[0];if tls.read(&mut byte).await?!=0{return Err("trailing data".into())}
 Ok(())
}
