//! Bounded, real loopback TLS/Spiral lifecycle checks through public APIs only.
//!
//! Credentials are supplied by the caller and never printed. Synthetic short
//! AsyncWrite and deadline tests live separately in the channel unit suite.
#![forbid(unsafe_code)]

use serde_json::{json, Value};
use spiral_protocol::{
    admission::Admission,
    channel::Session,
    handshake::{self, Pin as AuthPin},
    identity::ServerIdentity,
    transport::{self, Transport},
    worker::KemPool,
    Error,
};
use std::{
    env,
    future::{poll_fn, Future},
    io::Write,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::{TcpListener, TcpStream};

type ProbeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const NAME: &str = "spiral-lab.example";
const SERVICE: &str = "spiral-research";
const CASES: [&str; 6] = [
    "simultaneous_close",
    "cancelled_send",
    "cancelled_receive",
    "cancelled_close_resume",
    "dropped_session_sender",
    "concurrent_senders",
];

fn require(condition: bool, message: &str) -> ProbeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}

struct Args {
    folder: PathBuf,
    rounds: usize,
    seed: u64,
}

impl Args {
    fn read() -> ProbeResult<Self> {
        let mut args = env::args().skip(1);
        let mut folder = None;
        let mut rounds = None;
        let mut seed = None;
        while let Some(option) = args.next() {
            let value = args.next().ok_or("missing option value")?;
            match option.as_str() {
                "--fixture-dir" if folder.is_none() => folder = Some(PathBuf::from(value)),
                "--rounds" if rounds.is_none() => rounds = Some(value.parse::<usize>()?),
                "--seed" if seed.is_none() => seed = Some(value.parse::<u64>()?),
                _ => return Err("unknown or duplicate option".into()),
            }
        }
        let rounds = rounds.unwrap_or(4);
        require((1..=100).contains(&rounds), "rounds must be 1..100")?;
        Ok(Self {
            folder: folder.ok_or("--fixture-dir is required")?,
            rounds,
            seed: seed.unwrap_or(20261108),
        })
    }
}

struct Config {
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
    identity: Arc<ServerIdentity>,
    pin: AuthPin,
}

impl Config {
    fn load(folder: &Path) -> ProbeResult<Self> {
        let identity = ServerIdentity::load(&folder.join("auth.bin"))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let pin = AuthPin {
            public_key: identity.public_key(),
            not_before: now.saturating_sub(60),
            not_after: now.checked_add(3600).ok_or("pin time overflow")?,
            revoked: false,
        };
        Ok(Self {
            client: transport::client_config(&folder.join("ca.pem"))?,
            server: transport::server_config(&folder.join("cert.pem"), &folder.join("key.pem"))?,
            identity,
            pin,
        })
    }
}

struct Pair {
    client: Session,
    server: Session,
    admission: Admission,
    sid: [u8; 16],
}

async fn authenticated_pair(config: &Config, pool: &KemPool) -> ProbeResult<Pair> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let admission = Admission::default();
    let gate = admission.clone();
    let accept = async {
        let (socket, peer) = listener.accept().await?;
        let lease = gate.acquire(peer.ip())?;
        let transport = Transport::accept(socket, config.server.clone(), NAME).await?;
        handshake::server(
            transport,
            NAME,
            SERVICE,
            config.identity.clone(),
            pool,
            lease,
        )
        .await
    };
    let connect = async {
        let socket = TcpStream::connect(address).await?;
        let transport = Transport::connect(socket, config.client.clone(), NAME).await?;
        handshake::client(transport, NAME, SERVICE, config.pin.clone(), pool).await
    };
    let (client, server) = tokio::try_join!(connect, accept)?;
    let c = client.info();
    let s = server.info();
    require(
        c.sid == s.sid && c.sid != [0; 16],
        "authenticated session IDs differ",
    )?;
    require(
        c.transcript == s.transcript,
        "authenticated transcripts differ",
    )?;
    require(
        c.binding_hash == s.binding_hash,
        "TLS exporter bindings differ",
    )?;
    require(
        admission.counts()? == (1, 0),
        "established admission was not retained",
    )?;
    Ok(Pair {
        client: client.start()?,
        server: server.start()?,
        admission,
        sid: c.sid,
    })
}

fn payload(seed: u64, id: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| {
            (seed as u8)
                .wrapping_add(id.wrapping_mul(17))
                .wrapping_add((index as u8).wrapping_mul(13))
        })
        .collect()
}

/// This process has a current-thread runtime. A first poll of a fresh send can
/// enqueue work, but the separately spawned writer cannot run until we yield.
/// Dropping this future cancels the API waiter, not the owned queued plaintext.
async fn cancel_after_first_pending<F: Future>(future: F) -> ProbeResult<()> {
    let mut future = Box::pin(future);
    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())),
        Poll::Ready(_) => Poll::Ready(Err("operation completed before cancellation point".into())),
    })
    .await?;
    drop(future);
    Ok(())
}

async fn clean_close(pair: &mut Pair) -> ProbeResult<()> {
    let (client, server) = tokio::join!(pair.client.close(), pair.server.close());
    client?;
    server?;
    require(
        pair.admission.counts()? == (0, 0),
        "clean close retained admission",
    )?;
    require(
        matches!(pair.client.send(b"after-close").await, Err(Error::Closed))
            && matches!(pair.server.send(b"after-close").await, Err(Error::Closed)),
        "send accepted after clean close",
    )
}

async fn admission_released(admission: &Admission) -> ProbeResult<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if admission.counts()? == (0, 0) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .map_err(|_| "admission cleanup watchdog elapsed")??;
    Ok(())
}

async fn run_case(
    id: &str,
    round: usize,
    seed: u64,
    config: &Config,
    pool: &KemPool,
) -> ProbeResult<Value> {
    let mut pair = authenticated_pair(config, pool).await?;
    let session_id = hex::encode(pair.sid);
    let length = [1, 31, 1024, 16384][(seed.wrapping_add(round as u64) % 4) as usize];
    let value = payload(seed.wrapping_add(round as u64), 0, length);
    let mut delivered = 0;
    let mut cancelled = 0;
    let mut clean = true;
    match id {
        "simultaneous_close" => {
            pair.client.send(&value).await?;
            require(
                pair.server.receive().await?.as_bytes() == value,
                "client DATA changed",
            )?;
            pair.server.send(&value).await?;
            require(
                pair.client.receive().await?.as_bytes() == value,
                "server DATA changed",
            )?;
            delivered = 2;
            clean_close(&mut pair).await?;
        }
        "cancelled_send" => {
            cancel_after_first_pending(pair.client.send(&value)).await?;
            cancelled = 1;
            let next = payload(seed.wrapping_add(round as u64), 1, length);
            pair.client.send(&next).await?;
            require(
                pair.server.receive().await?.as_bytes() == value,
                "cancelled waiter lost committed DATA",
            )?;
            require(
                pair.server.receive().await?.as_bytes() == next,
                "DATA duplicated or reordered after cancellation",
            )?;
            delivered = 2;
            clean_close(&mut pair).await?;
        }
        "cancelled_receive" => {
            cancel_after_first_pending(pair.server.receive()).await?;
            cancelled = 1;
            pair.client.send(&value).await?;
            require(
                pair.server.receive().await?.as_bytes() == value,
                "cancelled receive lost DATA",
            )?;
            delivered = 1;
            clean_close(&mut pair).await?;
        }
        "cancelled_close_resume" => {
            pair.client.send(&value).await?;
            require(
                pair.server.receive().await?.as_bytes() == value,
                "pre-close DATA changed",
            )?;
            delivered = 1;
            cancel_after_first_pending(pair.client.close()).await?;
            cancelled = 1;
            clean_close(&mut pair).await?;
        }
        "dropped_session_sender" => {
            let admission = pair.admission.clone();
            let sender = pair.client.sender();
            drop(pair.client);
            require(
                matches!(sender.send(&value).await, Err(Error::Closed)),
                "retained sender survived Session drop",
            )?;
            require(
                matches!(pair.server.receive().await, Err(Error::Closed)),
                "abrupt session drop was accepted as clean receive",
            )?;
            require(
                matches!(pair.server.close().await, Err(Error::Closed)),
                "abrupt session drop was accepted as clean close",
            )?;
            drop(sender);
            drop(pair.server);
            admission_released(&admission).await?;
            clean = false;
        }
        "concurrent_senders" => {
            let mut jobs = tokio::task::JoinSet::new();
            let mut expected = Vec::new();
            for lane in 0..4u8 {
                let sender = pair.client.sender();
                let messages: Vec<Vec<u8>> = (0..4u8)
                    .map(|offset| {
                        payload(seed.wrapping_add(round as u64), lane * 4 + offset, length)
                    })
                    .collect();
                expected.extend(messages.iter().cloned());
                jobs.spawn(async move {
                    for message in messages {
                        sender.send(&message).await?;
                    }
                    Ok::<_, Error>(())
                });
            }
            let mut received = Vec::new();
            for _ in 0..expected.len() {
                received.push(pair.server.receive().await?.as_bytes().to_vec());
            }
            while let Some(result) = jobs.join_next().await {
                result??;
            }
            received.sort();
            expected.sort();
            require(
                received == expected,
                "concurrent send DATA was lost, changed, or duplicated",
            )?;
            delivered = received.len();
            clean_close(&mut pair).await?;
        }
        _ => return Err("unknown case".into()),
    }
    require(
        pool.metrics().live_keys == 0,
        "completed handshake retained a native key",
    )?;
    Ok(json!({
        "id":id,"round":round,"status":"passed","session_id":session_id,
        "authenticated_pair":true,"matching_transcript_and_binding":true,
        "delivered":delivered,"cancelled_waiters":cancelled,
        "clean_close":clean,"admission_released":true,
        "scope":"real authenticated loopback TLS; no synthetic short-write claim"
    }))
}

async fn run(args: Args) -> ProbeResult<()> {
    let config = Config::load(&args.folder)?;
    let pool = KemPool::new(2)?;
    let mut completed = 0;
    let mut failure = None;
    for round in 0..args.rounds {
        for id in CASES {
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                run_case(id, round, args.seed, &config, &pool),
            )
            .await;
            match result {
                Ok(Ok(value)) => {
                    println!("LIFECYCLE_TLS_CASE {value}");
                    std::io::stdout().flush()?;
                    completed += 1;
                }
                Ok(Err(error)) => {
                    failure = Some(format!("{id} round {round}: {error}"));
                    break;
                }
                Err(_) => {
                    failure = Some(format!("{id} round {round}: case watchdog elapsed"));
                    break;
                }
            }
        }
        if failure.is_some() {
            break;
        }
    }
    // Report shutdown/identity failures as failures too; never hide them behind
    // successful case output. The worker join runs independently of its caller.
    let shutdown = tokio::time::timeout(Duration::from_secs(5), pool.shutdown()).await;
    if !matches!(shutdown, Ok(Ok(()))) {
        failure.get_or_insert_with(|| "KEM worker shutdown failed or timed out".to_owned());
    }
    if let Err(error) = config.identity.close() {
        failure.get_or_insert_with(|| format!("identity close: {error}"));
    }
    let metrics = pool.metrics();
    let auth_closed = config.identity.is_closed()?;
    if metrics.live_keys != 0 || !auth_closed {
        failure.get_or_insert_with(|| "secret owner cleanup incomplete".to_owned());
    }
    if failure.is_none()
        && (completed != args.rounds * CASES.len()
            || metrics.executed != completed as u64 * 3
            || metrics.rejected != 0)
    {
        failure = Some("case count or KEM execution accounting mismatch".to_owned());
    }
    println!(
        "{}",
        json!({"status":if failure.is_none(){"passed"}else{"failed"},
        "case_count":completed,"rounds":args.rounds,"seed":args.seed,
        "kem":{"live_keys":metrics.live_keys,"executed_jobs":metrics.executed,"rejected_jobs":metrics.rejected},
        "auth_key_closed":auth_closed,"error":failure})
    );
    if failure.is_some() {
        Err("lifecycle probe failed".into())
    } else {
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let result = match Args::read() {
        Ok(args) => run(args).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("lifecycle probe: {error}");
        std::process::exit(1);
    }
}
