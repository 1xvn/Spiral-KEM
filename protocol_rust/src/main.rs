//! Loopback-only executable. Credentials are explicitly supplied by the caller.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use spiral_protocol::{
    admission::Admission,
    handshake::{self, Pin},
    identity::ServerIdentity,
    key_backup::{self, KeyKind},
    transport::{self, Transport},
    worker::KemPool,
    Error, Result,
};
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::{TcpListener, TcpStream};
struct CloseIdentityOnDrop(Arc<ServerIdentity>);
impl Drop for CloseIdentityOnDrop {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}
struct Args {
    mode: String,
    values: BTreeMap<String, String>,
}
impl Args {
    fn read() -> Result<Self> {
        let mut a = std::env::args().skip(1);
        let mode = a.next().ok_or(Error::Input)?;
        let mut values = BTreeMap::new();
        while let Some(k) = a.next() {
            if ![
                "--name",
                "--service",
                "--port",
                "--connections",
                "--workers",
                "--messages",
                "--payload",
                "--pipeline",
                "--cert",
                "--key",
                "--auth",
                "--ca",
                "--pin",
                "--recovery-key",
                "--backup",
                "--expected-public-key-sha256",
            ]
            .contains(&k.as_str())
                || values.contains_key(&k)
            {
                return Err(Error::Input);
            }
            values.insert(k, a.next().ok_or(Error::Input)?);
        }
        Ok(Self { mode, values })
    }
    fn get(&self, name: &str) -> Result<&str> {
        self.values
            .get(name)
            .map(String::as_str)
            .ok_or(Error::Input)
    }
    fn number(&self, name: &str, default: usize) -> Result<usize> {
        self.values
            .get(name)
            .map_or(Ok(default), |v| v.parse().map_err(|_| Error::Input))
    }
}
fn require_options(a: &Args, expected: &[&str]) -> Result<()> {
    if a.values.len() != expected.len()
        || expected.iter().any(|name| !a.values.contains_key(*name))
    {
        return Err(Error::Input);
    }
    Ok(())
}
fn administration(a: &Args) -> Result<Value> {
    match a.mode.as_str() {
        "auth-keygen" | "auth-public" => {
            require_options(a, &["--auth"])?;
            let path = Path::new(a.get("--auth")?);
            let public = if a.mode == "auth-keygen" {
                ServerIdentity::generate(path)?
            } else {
                let identity = ServerIdentity::load(path)?;
                let public = identity.public_key();
                identity.close()?;
                public
            };
            use sha2::{Digest, Sha256};
            Ok(json!({
                "status": if a.mode == "auth-keygen" { "created" } else { "loaded" },
                "public_key_hex": hex::encode(public),
                "public_key_sha256": hex::encode(Sha256::digest(public)),
            }))
        }
        "recovery-keygen" => {
            require_options(a, &["--recovery-key"])?;
            key_backup::generate_recovery_key(Path::new(a.get("--recovery-key")?))?;
            Ok(json!({"status":"created", "operation":"recovery-keygen"}))
        }
        "tls-public" => {
            require_options(a, &["--key"])?;
            let fingerprint =
                key_backup::public_fingerprint(KeyKind::TlsPem, Path::new(a.get("--key")?))?;
            Ok(json!({"status":"loaded", "key_kind":"tls-private-key",
                      "public_key_sha256":hex::encode(fingerprint)}))
        }
        "auth-backup" | "tls-backup" | "auth-restore" | "tls-restore" => {
            let (kind, source_option, kind_name) = if a.mode.starts_with("auth-") {
                (KeyKind::AuthSeed, "--auth", "auth-seed")
            } else {
                (KeyKind::TlsPem, "--key", "tls-private-key")
            };
            let restoring = a.mode.ends_with("-restore");
            let mut options = vec![source_option, "--recovery-key", "--backup"];
            if restoring {
                options.push("--expected-public-key-sha256");
            }
            require_options(a, &options)?;
            let key = Path::new(a.get(source_option)?);
            let recovery = Path::new(a.get("--recovery-key")?);
            let backup = Path::new(a.get("--backup")?);
            let fingerprint = if restoring {
                let text = a.get("--expected-public-key-sha256")?;
                if text.len() != 64 {
                    return Err(Error::Input);
                }
                let expected: [u8; 32] = hex::decode(text)
                    .map_err(|_| Error::Input)?
                    .try_into()
                    .map_err(|_| Error::Input)?;
                key_backup::restore(kind, backup, recovery, key, expected)?
            } else {
                key_backup::backup(kind, key, recovery, backup)?
            };
            Ok(json!({"status":if restoring {"restored"} else {"backed-up"},
                      "key_kind":kind_name,"public_key_sha256":hex::encode(fingerprint)}))
        }
        _ => Err(Error::Input),
    }
}
fn pin(path: &Path, name: &str, service: &str) -> Result<Pin> {
    let v: Value = serde_json::from_reader(std::fs::File::open(path)?).map_err(|_| Error::Input)?;
    if v["server_name"].as_str() != Some(name) || v["service"].as_str() != Some(service) {
        return Err(Error::Input);
    }
    let public_key = hex::decode(v["public_key_hex"].as_str().ok_or(Error::Input)?)
        .map_err(|_| Error::Input)?
        .try_into()
        .map_err(|_| Error::Input)?;
    Ok(Pin {
        public_key,
        not_before: v["not_before"].as_u64().ok_or(Error::Input)?,
        not_after: v["not_after"].as_u64().ok_or(Error::Input)?,
        revoked: v["revoked"].as_bool().ok_or(Error::Input)?,
    })
}
fn payload(id: usize, size: usize) -> Vec<u8> {
    let mut v = vec![b'x'; size];
    for (i, b) in (id as u64)
        .to_be_bytes()
        .iter()
        .take(size.min(8))
        .enumerate()
    {
        v[i] = *b;
    }
    v
}
async fn one_client(port: u16, a: &Args, pool: &KemPool) -> Result<Value> {
    let name = a.get("--name")?;
    let service = a.get("--service")?;
    handshake::validate_identity(name, service)?;
    let n = a.number("--messages", 1)?;
    let size = a.number("--payload", 64)?;
    let pipeline = a.number("--pipeline", 1)?;
    if !(1..=1024).contains(&n) || !(1..=16384).contains(&size) || !(1..=8).contains(&pipeline) {
        return Err(Error::Input);
    }
    let cfg = transport::client_config(Path::new(a.get("--ca")?))?;
    let pin = pin(Path::new(a.get("--pin")?), name, service)?;
    let start = Instant::now();
    let sock = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)),
    )
    .await??;
    let tcp_ms = start.elapsed().as_secs_f64() * 1000.;
    let tls_started = Instant::now();
    let io = Transport::connect(sock, cfg, name).await?;
    let tls_ms = tls_started.elapsed().as_secs_f64() * 1000.;
    let binding = io.binding_hash();
    let spiral_started = Instant::now();
    let ready = handshake::client(io, name, service, pin, pool).await?;
    let spiral_ms = spiral_started.elapsed().as_secs_f64() * 1000.;
    let sid = ready.info().sid;
    let transcript = ready.info().transcript;
    let hs_ms = start.elapsed().as_secs_f64() * 1000.;
    let mut session = ready.start()?;
    let app_started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for lane in 0..pipeline {
        let sender = session.sender();
        tasks.spawn(async move {
            for id in (lane..n).step_by(pipeline) {
                sender.send(&payload(id, size)).await?;
            }
            Ok::<_, Error>(())
        });
    }
    let mut got = Vec::with_capacity(n);
    for _ in 0..n {
        got.push(session.receive().await?.as_bytes().to_vec());
    }
    while let Some(r) = tasks.join_next().await {
        r.map_err(|_| Error::Internal)??;
    }
    let app_ms = app_started.elapsed().as_secs_f64() * 1000.;
    let mut expected: Vec<_> = (0..n).map(|i| payload(i, size)).collect();
    got.sort();
    expected.sort();
    if got != expected {
        return Err(Error::Authentication);
    }
    session.close().await?;
    Ok(
        json!({"session_id":hex::encode(sid),"binding_hash":hex::encode(binding),"transcript_hash":hex::encode(transcript),"handshake_ms":hs_ms,"tcp_ms":tcp_ms,"tls_ms":tls_ms,"spiral_ms":spiral_ms,"app_ms":app_ms,"total_ms":start.elapsed().as_secs_f64()*1000.,"messages":n,"payload_bytes":size,"authenticated_close":true}),
    )
}
async fn run(a: &Args, pool: &KemPool) -> Result<Value> {
    let count = a.number("--connections", 1)?;
    if !(1..=64).contains(&count) {
        return Err(Error::Input);
    }
    let port: u16 = a
        .number("--port", 0)?
        .try_into()
        .map_err(|_| Error::Input)?;
    let name = a.get("--name")?;
    let service = a.get("--service")?;
    handshake::validate_identity(name, service)?;
    match a.mode.as_str() {
        "server" => {
            let cfg =
                transport::server_config(Path::new(a.get("--cert")?), Path::new(a.get("--key")?))?;
            let signing = handshake::load_signing_key(Path::new(a.get("--auth")?))?;
            let _auth_close = CloseIdentityOnDrop(signing.clone());
            let messages = a.number("--messages", 1)?;
            if !(1..=1024).contains(&messages) {
                return Err(Error::Input);
            }
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
            println!(
                "{}",
                json!({"listening":listener.local_addr()?.port(),"loopback_only":true})
            );
            std::io::stdout().flush()?;
            let admission = Admission::default();
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..count {
                let (sock, peer) =
                    tokio::time::timeout(Duration::from_secs(10), listener.accept()).await??;
                let cfg = cfg.clone();
                let signing = signing.clone();
                let p = pool.clone();
                let name = name.to_owned();
                let service = service.to_owned();
                let gate = admission.clone();
                tasks.spawn(async move{
                    let lease=gate.acquire(peer.ip())?;let io=Transport::accept(sock,cfg,&name).await?;let binding=io.binding_hash();
                    let ready=handshake::server(io,&name,&service,signing,&p,lease).await?;
                    let sid=ready.info().sid;let transcript=ready.info().transcript;
                    let mut session=ready.start()?;
                    for _ in 0..messages{let value=session.receive().await?;session.send(value.as_bytes()).await?;}
                    session.close().await?;
                    Ok::<_,Error>(json!({"session_id":hex::encode(sid),"binding_hash":hex::encode(binding),"transcript_hash":hex::encode(transcript),"messages":messages,"authenticated_close":true}))
                });
            }
            let mut results = Vec::new();
            let mut failure = None;
            while let Some(r) = tasks.join_next().await {
                match r.map_err(|_| Error::Internal)? {
                    Ok(v) => results.push(v),
                    Err(e) => failure = Some(e),
                }
            }
            if let Some(e) = failure {
                return Err(e);
            }
            if admission.counts()? != (0, 0) {
                return Err(Error::Internal);
            }
            signing.close()?;
            Ok(
                json!({"status":"passed","role":"server","connections":count,"sessions":results,"admission_released":true,"auth_key_closed":signing.is_closed()?}),
            )
        }
        "client" => {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..count {
                let args = Args {
                    mode: a.mode.clone(),
                    values: a.values.clone(),
                };
                let p = pool.clone();
                tasks.spawn(async move { one_client(port, &args, &p).await });
            }
            let mut results = Vec::new();
            let mut failure = None;
            while let Some(r) = tasks.join_next().await {
                match r.map_err(|_| Error::Internal)? {
                    Ok(v) => results.push(v),
                    Err(e) => failure = Some(e),
                }
            }
            if let Some(e) = failure {
                return Err(e);
            }
            Ok(json!({"status":"passed","role":"client","connections":count,"sessions":results}))
        }
        _ => Err(Error::Input),
    }
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let a = Args::read()?;
    // File-only administration never initializes KEM workers or opens a listener.
    if matches!(
        a.mode.as_str(),
        "auth-keygen" | "auth-public" | "recovery-keygen" | "tls-public"
            | "auth-backup" | "tls-backup" | "auth-restore" | "tls-restore"
    ) {
        match administration(&a) {
            Ok(report) => {
                println!("{report}");
                return Ok(());
            }
            Err(error) => {
                println!("{}", json!({"status":"failed","operation":a.mode}));
                return Err(error);
            }
        }
    }
    if !matches!(a.mode.as_str(), "server" | "client")
        || ["--recovery-key", "--backup", "--expected-public-key-sha256"]
            .iter()
            .any(|name| a.values.contains_key(*name))
    {
        return Err(Error::Input);
    }
    let pool = KemPool::new(a.number("--workers", KemPool::default_workers())?)?;
    let result = run(&a, &pool).await;
    pool.shutdown().await?;
    let m = pool.metrics();
    if m.live_keys != 0 {
        return Err(Error::Internal);
    }
    let metrics =
        json!({"live_keys":m.live_keys,"executed_jobs":m.executed,"rejected_jobs":m.rejected});
    match result {
        Ok(mut report) => {
            report["kem"] = metrics;
            println!("{report}");
            Ok(())
        }
        Err(e) => {
            println!("{}", json!({"status":"failed","kem":metrics}));
            Err(e)
        }
    }
}
