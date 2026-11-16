//! Bounded, real loopback TCP/TLS/Spiral load through public APIs.
//! Process measurements include both endpoints. This is not a capacity claim.
#![forbid(unsafe_code)]

use serde_json::{json, Value};
use spiral_protocol::{
    admission::Admission,
    channel::Session,
    handshake::{self, Pin},
    identity::ServerIdentity,
    transport::{self, Transport},
    worker::KemPool,
    Error,
};
use std::{
    collections::HashSet,
    env,
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}, Arc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::{TcpListener, TcpSocket, TcpStream}, task::JoinSet};

type ProbeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const NAME: &str = "spiral-lab.example";
const SERVICE: &str = "spiral-research";
const SCOPE: &str = "One persistent process, listener, admission gate and KEM pool; actual loopback TCP/TLS 1.3 plus authenticated Spiral; process resources include both endpoints; no production capacity claim";
const GROUP_SETUP_SECONDS: u64 = 30;
const CLOSE_DEADLINE_SECONDS: u64 = 10;

fn require(condition: bool, message: &str) -> ProbeResult<()> {
    if condition { Ok(()) } else { Err(message.to_owned().into()) }
}
fn emit(value: Value) -> ProbeResult<()> {
    println!("{value}");
    std::io::stdout().flush()?;
    Ok(())
}
fn resource_count(directory: &str) -> Option<usize> {
    std::fs::read_dir(directory).ok().map(|entries| entries.filter_map(Result::ok).count())
}

struct Args {
    folder: PathBuf,
    duration: u64,
    connections: usize,
    interval_ms: u64,
    payload: usize,
    workers: usize,
}
impl Args {
    fn read() -> ProbeResult<Self> {
        let mut values = std::collections::BTreeMap::new();
        let mut args = env::args().skip(1);
        while let Some(option) = args.next() {
            require(["--fixture-dir", "--duration-seconds", "--connections", "--interval-ms", "--payload", "--workers"].contains(&option.as_str()), "unknown option")?;
            let value = args.next().ok_or("missing option value")?;
            require(values.insert(option, value).is_none(), "duplicate option")?;
        }
        let number = |name: &str, default: u64| -> ProbeResult<u64> {
            values.get(name).map_or(Ok(default), |value| Ok(value.parse()?))
        };
        let result = Self {
            folder: PathBuf::from(values.get("--fixture-dir").ok_or("--fixture-dir is required")?),
            duration: number("--duration-seconds", 1800)?,
            connections: number("--connections", 64)?.try_into()?,
            interval_ms: number("--interval-ms", 20)?,
            payload: number("--payload", 16384)?.try_into()?,
            workers: number("--workers", 2)?.try_into()?,
        };
        require((1..=86400).contains(&result.duration), "duration must be 1..86400 seconds")?;
        require((1..=64).contains(&result.connections), "connections must be 1..64")?;
        require((1..=10000).contains(&result.interval_ms), "interval must be 1..10000 milliseconds")?;
        require((1..=16384).contains(&result.payload), "payload must be 1..16384 bytes")?;
        require((1..=4).contains(&result.workers), "workers must be 1..4")?;
        Ok(result)
    }
}

struct Config {
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
    identity: Arc<ServerIdentity>,
    pin: Pin,
}
impl Config {
    fn load(folder: &Path) -> ProbeResult<Self> {
        let identity = ServerIdentity::load(&folder.join("auth.bin"))?;
        let value: Value = serde_json::from_reader(std::fs::File::open(folder.join("pin.json"))?)?;
        require(value["server_name"] == NAME && value["service"] == SERVICE, "fixture pin identity differs")?;
        let public_key: [u8; 32] = hex::decode(value["public_key_hex"].as_str().ok_or("missing public key")?)?.try_into().map_err(|_| "invalid public key length")?;
        require(public_key == identity.public_key(), "fixture pin does not match authentication identity")?;
        Ok(Self {
            client: transport::client_config(&folder.join("ca.pem"))?,
            server: transport::server_config(&folder.join("cert.pem"), &folder.join("key.pem"))?,
            identity,
            pin: Pin {
                public_key,
                not_before: value["not_before"].as_u64().ok_or("missing pin not_before")?,
                not_after: value["not_after"].as_u64().ok_or("missing pin not_after")?,
                revoked: value["revoked"].as_bool().ok_or("missing pin revoked")?,
            },
        })
    }
}
#[derive(Default)]
struct Stats {
    messages: AtomicU64,
    bytes: AtomicU64,
    pairs: AtomicU64,
    rejections: AtomicU64,
    epochs: AtomicU64,
    closes: AtomicU64,
    peak: AtomicUsize,
    per_ip_passed: AtomicBool,
    pending_passed: AtomicBool,
    global_passed: AtomicBool,
}
struct Pair {
    client: Session,
    server: Session,
    sid: [u8; 16],
}
async fn socket(address: SocketAddr, source: Ipv4Addr) -> ProbeResult<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind((source, 0).into())?;
    Ok(tokio::time::timeout(Duration::from_secs(3), socket.connect(address)).await??)
}
async fn pair(listener: &TcpListener, admission: &Admission, config: &Config, pool: &KemPool, stats: &Stats, source: Ipv4Addr) -> ProbeResult<Pair> {
    let address = listener.local_addr()?;
    let connect = async {
        let stream = socket(address, source).await?;
        let transport = Transport::connect(stream, config.client.clone(), NAME).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(handshake::client(transport, NAME, SERVICE, config.pin.clone(), pool).await?)
    };
    let accept = async {
        let (stream, peer) = listener.accept().await?;
        require(peer.ip() == source, "actual accepted source IP differs from requested bind")?;
        let lease = admission.acquire(peer.ip())?;
        let transport = Transport::accept(stream, config.server.clone(), NAME).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(handshake::server(transport, NAME, SERVICE, config.identity.clone(), pool, lease).await?)
    };
    let (client, server) = tokio::time::timeout(Duration::from_secs(22), async { tokio::try_join!(connect, accept) }).await??;
    let c = client.info();
    let s = server.info();
    require(c.sid != [0; 16] && c.sid == s.sid && c.transcript == s.transcript && c.binding_hash == s.binding_hash, "authenticated IDs, transcripts or TLS bindings differ")?;
    let pair = Pair { client: client.start()?, server: server.start()?, sid: c.sid };
    stats.pairs.fetch_add(1, Ordering::Relaxed);
    stats.peak.fetch_max(admission.counts()?.0, Ordering::Relaxed);
    Ok(pair)
}
async fn clean_close(mut pair: Pair, stats: &Stats) -> ProbeResult<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, server) = tokio::join!(pair.client.close(), pair.server.close());
        client?;
        server?;
        require(matches!(pair.client.send(b"closed").await, Err(Error::Closed)) && matches!(pair.server.send(b"closed").await, Err(Error::Closed)), "send accepted after authenticated close")
    }).await??;
    stats.closes.fetch_add(1, Ordering::Relaxed);
    Ok(())
}
async fn rejection(listener: &TcpListener, admission: &Admission, stats: &Stats, source: Ipv4Addr) -> ProbeResult<()> {
    let connect = socket(listener.local_addr()?, source);
    let (client, accepted) = tokio::time::timeout(Duration::from_secs(4), async { tokio::join!(connect, listener.accept()) }).await?;
    let _client = client?;
    let (_server, peer) = accepted?;
    require(peer.ip() == source, "rejection socket source IP differs")?;
    require(matches!(admission.acquire(peer.ip()), Err(Error::QueueFull)), "over-capacity real connection was not rejected as QueueFull")?;
    stats.rejections.fetch_add(1, Ordering::Relaxed);
    Ok(())
}
async fn admission_empty(admission: &Admission) -> ProbeResult<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if admission.counts()? == (0, 0) { return Ok::<_, Error>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    Ok(())
}
async fn limits(listener: &TcpListener, admission: &Admission, config: &Config, pool: &KemPool, stats: &Stats) -> ProbeResult<()> {
    let source = Ipv4Addr::new(127, 3, 0, 1);
    let mut held = Vec::new();
    for _ in 0..4 { held.push(pair(listener, admission, config, pool, stats, source).await?); }
    require(admission.counts()? == (4, 0), "per-IP test did not retain four authenticated sessions")?;
    rejection(listener, admission, stats, source).await?;
    for pair in held { clean_close(pair, stats).await?; }
    admission_empty(admission).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    clean_close(pair(listener, admission, config, pool, stats, source).await?, stats).await?;
    admission_empty(admission).await?;
    stats.per_ip_passed.store(true, Ordering::Relaxed);
    emit(json!({"event":"limit_case","id":"per_ip_four_then_fifth_rejected_and_refill_recovered","status":"passed","authenticated_pairs":5,"rejected":1}))?;

    let mut sockets = Vec::new();
    let mut waiting = JoinSet::new();
    let started = Instant::now();
    for i in 1..=32 {
        let source = Ipv4Addr::new(127, 4, 0, i);
        let (client, accepted) = tokio::join!(socket(listener.local_addr()?, source), listener.accept());
        sockets.push(client?);
        let (server, peer) = accepted?;
        require(peer.ip() == source, "pending socket source IP differs")?;
        let lease = admission.acquire(peer.ip())?;
        let tls = config.server.clone();
        waiting.spawn(async move {
            let result = Transport::accept(server, tls, NAME).await;
            drop(lease);
            require(matches!(result, Err(Error::Deadline)), "idle TLS connection failed without its production timeout")
        });
    }
    require(admission.counts()? == (32, 32), "pending test did not reach the production pending limit")?;
    rejection(listener, admission, stats, Ipv4Addr::new(127, 4, 0, 33)).await?;
    tokio::time::timeout(Duration::from_secs(13), async {
        while let Some(result) = waiting.join_next().await { result??; }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await??;
    drop(sockets);
    admission_empty(admission).await?;
    clean_close(pair(listener, admission, config, pool, stats, Ipv4Addr::new(127, 4, 1, 1)).await?, stats).await?;
    admission_empty(admission).await?;
    stats.pending_passed.store(true, Ordering::Relaxed);
    emit(json!({"event":"limit_case","id":"pending_32_then_33rd_rejected_idle_tls_timeout_and_recovery","status":"passed","pending_peak":32,"rejected":1,"actual_elapsed_seconds":started.elapsed().as_secs_f64()}))?;
    Ok(())
}
fn sample(admission: &Admission, pool: &KemPool, stats: &Stats, elapsed: f64, expected: usize) -> ProbeResult<()> {
    let (active, pending) = admission.counts()?;
    let kem = pool.metrics();
    emit(json!({"event":"sample","phase":"soak","soak_elapsed_seconds":elapsed,"expected_established_connections":expected,"active":active,"pending":pending,"total_messages":stats.messages.load(Ordering::Relaxed),"echoed_bytes":stats.bytes.load(Ordering::Relaxed),"admission_rejected":stats.rejections.load(Ordering::Relaxed),"completed_epochs":stats.epochs.load(Ordering::Relaxed),"authenticated_pairs_total":stats.pairs.load(Ordering::Relaxed),"kem":{"live_keys":kem.live_keys,"executed_jobs":kem.executed,"rejected_jobs":kem.rejected}}))
}
async fn traffic(mut pair: Pair, lane: usize, payload_size: usize, interval_ms: u64, end: Instant, stats: Arc<Stats>) -> ProbeResult<(Pair, Instant)> {
    let mut value = vec![0u8; payload_size];
    let mut clock = tokio::time::interval(Duration::from_millis(interval_ms));
    clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut completed = 0u64;
    // Half the byte budget at maximum payload; also below the record budget.
    for sequence in 0..32768u64 {
        if Instant::now() >= end { break; }
        tokio::select! { _=clock.tick()=>{}, _=tokio::time::sleep_until(end.into())=>break }
        if Instant::now() >= end { break; }
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = (lane as u8).wrapping_mul(31).wrapping_add(sequence as u8).wrapping_add(index as u8);
        }
        for (target, byte) in value.iter_mut().zip(sequence.to_be_bytes()) { *target = byte; }
        for (target, byte) in value.iter_mut().skip(8).zip((lane as u64).to_be_bytes()) { *target = byte; }
        tokio::time::timeout(Duration::from_secs(5), async {
            pair.client.send(&value).await?;
            let received = pair.server.receive().await?;
            require(received.as_bytes() == value, "server received altered, duplicate or unexpected DATA")?;
            pair.server.send(received.as_bytes()).await?;
            drop(received);
            let echoed = pair.client.receive().await?;
            require(echoed.as_bytes() == value, "client received altered, duplicate or unexpected echo")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }).await??;
        completed += 1;
        stats.messages.fetch_add(1, Ordering::Relaxed);
        stats.bytes.fetch_add(payload_size as u64, Ordering::Relaxed);
    }
    require(completed > 0, "connection completed no verified echoes in traffic epoch")?;
    Ok((pair, Instant::now()))
}
async fn open_group(args: &Args, listener: &TcpListener, admission: &Admission, config: &Config, pool: &KemPool, stats: &Stats) -> ProbeResult<Vec<Pair>> {
    let started = Instant::now();
    let initial = stats.epochs.load(Ordering::Relaxed) == 0;
    emit(json!({"event":"rotation_started","phase":"rotation","initial":initial,"expected_established_connections":0,"setup_deadline_seconds":GROUP_SETUP_SECONDS,"completed_epochs":stats.epochs.load(Ordering::Relaxed)}))?;
    // Keep setup below the production idle timeout even for the first pair in
    // this sequential group, and report liveness while an individual pair waits.
    let opening = tokio::time::timeout(Duration::from_secs(GROUP_SETUP_SECONDS), async {
        let mut pairs = Vec::with_capacity(args.connections);
        let mut ids = HashSet::with_capacity(args.connections);
        for lane in 0..args.connections {
            let pair = pair(listener, admission, config, pool, stats, Ipv4Addr::new(127, 5, 0, lane as u8 + 1)).await?;
            require(ids.insert(pair.sid), "concurrent authenticated session ID repeated")?;
            pairs.push(pair);
        }
        require(admission.counts()? == (args.connections, 0), "ready group admission counts differ")?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(pairs)
    });
    tokio::pin!(opening);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;
    loop {
        tokio::select! {
            result=&mut opening=>{ return Ok(result??); },
            _=heartbeat.tick()=>{
                let (active, pending) = admission.counts()?;
                emit(json!({"event":"rotation_progress","phase":"rotation","initial":initial,"expected_established_connections":0,"setup_deadline_seconds":GROUP_SETUP_SECONDS,"setup_elapsed_seconds":started.elapsed().as_secs_f64(),"active":active,"pending":pending}))?;
            }
        }
    }
}
#[derive(Default)]
struct Timing { soak: f64, traffic: f64, rotation: f64, close_tail: f64 }
async fn exercise(args: &Args, listener: &TcpListener, admission: &Admission, config: &Config, pool: &KemPool, stats: Arc<Stats>, timing: &mut Timing) -> ProbeResult<()> {
    limits(listener, admission, config, pool, &stats).await?;
    let mut pairs = open_group(args, listener, admission, config, pool, &stats).await?;
    emit(json!({"event":"rotation_ready","phase":"soak","initial":true,"soak_elapsed_seconds":0,"expected_established_connections":args.connections,"active":admission.counts()?.0,"pending":0,"authenticated_pairs_total":stats.pairs.load(Ordering::Relaxed),"completed_epochs":0}))?;
    if args.connections == 64 {
        rejection(listener, admission, &stats, Ipv4Addr::new(127, 5, 1, 1)).await?;
        require(admission.counts()? == (64, 0), "global rejection disturbed established sessions")?;
        stats.global_passed.store(true, Ordering::Relaxed);
        emit(json!({"event":"limit_case","id":"active_64_then_65th_rejected","status":"passed","active_peak":64,"rejected":1}))?;
    }
    let started = Instant::now();
    emit(json!({"event":"soak_started","status":"running","expected_established_connections":args.connections,"active":admission.counts()?.0,"pending":0,"duration_seconds":args.duration,"rotation_max_seconds":240,"rotation_max_messages_per_connection":32768}))?;
    let mut samples = tokio::time::interval(Duration::from_secs(1));
    samples.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let epoch_started = Instant::now();
        let remaining = (args.duration as f64 - timing.traffic).max(0.5);
        let epoch_end = epoch_started + Duration::from_secs_f64(remaining.min(240.0));
        emit(json!({"event":"traffic_started","phase":"soak","soak_elapsed_seconds":started.elapsed().as_secs_f64(),"expected_established_connections":args.connections,"completed_epochs":stats.epochs.load(Ordering::Relaxed)}))?;
        let mut tasks = JoinSet::new();
        for (lane, pair) in pairs.drain(..).enumerate() {
            tasks.spawn(traffic(pair, lane, args.payload, args.interval_ms, epoch_end, stats.clone()));
        }
        let mut closing = JoinSet::new();
        let mut traffic_end = epoch_started;
        while !tasks.is_empty() {
            tokio::select! {
                result=tasks.join_next()=>{
                    let (pair, finished) = result.ok_or("traffic task disappeared")???;
                    traffic_end = traffic_end.max(finished);
                    let stats = stats.clone();
                    closing.spawn(async move { clean_close(pair, &stats).await });
                },
                result=closing.join_next(), if !closing.is_empty()=>{ result.ok_or("close task disappeared")???; },
                _=samples.tick()=>{ sample(admission,pool,&stats,started.elapsed().as_secs_f64(),args.connections)?; }
            }
        }
        timing.traffic += traffic_end.duration_since(epoch_started).as_secs_f64();
        emit(json!({"event":"closing_started","phase":"closing","soak_elapsed_seconds":started.elapsed().as_secs_f64(),"expected_established_connections":0,"close_deadline_seconds":CLOSE_DEADLINE_SECONDS,"completed_epochs":stats.epochs.load(Ordering::Relaxed)}))?;
        tokio::time::timeout(Duration::from_secs(CLOSE_DEADLINE_SECONDS), async {
            while let Some(result) = closing.join_next().await { result??; }
            admission_empty(admission).await
        }).await??;
        timing.close_tail += traffic_end.elapsed().as_secs_f64();
        stats.epochs.fetch_add(1, Ordering::Relaxed);
        require(pool.metrics().live_keys == 0, "completed traffic epoch retained a native key")?;
        timing.soak = started.elapsed().as_secs_f64();
        if timing.traffic >= args.duration as f64 { break; }
        let rotation_started = Instant::now();
        pairs = open_group(args, listener, admission, config, pool, &stats).await?;
        timing.rotation += rotation_started.elapsed().as_secs_f64();
        emit(json!({"event":"rotation_ready","phase":"soak","initial":false,"soak_elapsed_seconds":started.elapsed().as_secs_f64(),"expected_established_connections":args.connections,"active":admission.counts()?.0,"pending":0,"authenticated_pairs_total":stats.pairs.load(Ordering::Relaxed),"completed_epochs":stats.epochs.load(Ordering::Relaxed)}))?;
    }
    sample(admission, pool, &stats, started.elapsed().as_secs_f64(), 0)?;
    require(stats.messages.load(Ordering::Relaxed) >= args.connections as u64, "not every requested connection completed an echo")?;
    Ok(())
}
async fn run(args: Args) -> ProbeResult<()> {
    let config = Config::load(&args.folder)?;
    let pool = KemPool::new(args.workers)?;
    let admission = Admission::default();
    let stats = Arc::new(Stats::default());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let fd_baseline = resource_count("/proc/self/fd");
    let thread_baseline = resource_count("/proc/self/task");
    let process_started = Instant::now();
    emit(json!({"event":"start","schema":"spiral-load-probe/v1","status":"running","scope":SCOPE,"pid":std::process::id(),"unix_time_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"connections":args.connections,"duration_seconds":args.duration,"interval_ms":args.interval_ms,"payload_bytes":args.payload,"workers":args.workers,"source_ip_policy":"actual distinct 127/8 source addresses; production admission limits unchanged","resource_baseline":{"fd_count":fd_baseline,"thread_count":thread_baseline},"production_limits":{"active":64,"pending":32,"per_ip":4,"per_ip_burst":4,"per_ip_refill_per_second":1,"session_max_age_seconds":600,"session_idle_seconds":60}}))?;
    let mut timing = Timing::default();
    let mut failures = Vec::new();
    if let Err(error) = exercise(&args, &listener, &admission, &config, &pool, stats.clone(), &mut timing).await { failures.push(error.to_string()); }
    drop(listener);
    if let Err(error) = admission_empty(&admission).await { failures.push(format!("admission cleanup: {error}")); }
    if !matches!(tokio::time::timeout(Duration::from_secs(5), pool.shutdown()).await, Ok(Ok(()))) { failures.push("KEM shutdown failed or exceeded watchdog".to_owned()); }
    if let Err(error) = config.identity.close() { failures.push(format!("authentication identity close: {error}")); }
    let counts = admission.counts()?;
    let kem = pool.metrics();
    let auth_closed = config.identity.is_closed()?;
    let pairs = stats.pairs.load(Ordering::Relaxed);
    let final_fds = resource_count("/proc/self/fd");
    if counts != (0, 0) || kem.live_keys != 0 || !auth_closed { failures.push("final resource ownership counts are not zero/closed".to_owned()); }
    if stats.closes.load(Ordering::Relaxed) != pairs { failures.push("not all authenticated session pairs completed authenticated close".to_owned()); }
    if !stats.per_ip_passed.load(Ordering::Relaxed) || !stats.pending_passed.load(Ordering::Relaxed) || (args.connections == 64 && !stats.global_passed.load(Ordering::Relaxed)) { failures.push("required admission limit check did not complete".to_owned()); }
    if kem.executed != pairs * 3 || kem.rejected != 0 { failures.push("unexpected KEM execution or rejection accounting".to_owned()); }
    if matches!((fd_baseline, final_fds), (Some(before), Some(after)) if after > before) { failures.push("final descriptor count exceeds initialized baseline".to_owned()); }
    emit(json!({"event":"final","schema":"spiral-load-probe/v1","status":if failures.is_empty(){"passed"}else{"failed"},"scope":SCOPE,"requested_duration_seconds":args.duration,"soak_elapsed_seconds":timing.soak,"traffic_epoch_elapsed_seconds":timing.traffic,"rotation_setup_seconds":timing.rotation,"close_tail_seconds":timing.close_tail,"actual_elapsed_seconds":process_started.elapsed().as_secs_f64(),"total_messages":stats.messages.load(Ordering::Relaxed),"echoed_bytes":stats.bytes.load(Ordering::Relaxed),"bidirectional_payload_bytes":stats.bytes.load(Ordering::Relaxed)*2,"authenticated_pairs_total":pairs,"authenticated_pair_closes":stats.closes.load(Ordering::Relaxed),"successful_endpoint_handshakes":pairs*2,"peak_authenticated_connections":stats.peak.load(Ordering::Relaxed),"limit_checks":{"per_ip":stats.per_ip_passed.load(Ordering::Relaxed),"pending":stats.pending_passed.load(Ordering::Relaxed),"global":if args.connections==64 {Some(stats.global_passed.load(Ordering::Relaxed))}else{None}},"completed_epochs":stats.epochs.load(Ordering::Relaxed),"admission_rejected":stats.rejections.load(Ordering::Relaxed),"active":counts.0,"pending":counts.1,"admission_released":counts==(0,0),"authenticated_close_for_all_completed_pairs":failures.is_empty(),"auth_key_closed":auth_closed,"resource_baseline":{"fd_count":fd_baseline,"thread_count":thread_baseline},"final_resources":{"fd_count":final_fds,"thread_count":resource_count("/proc/self/task")},"kem":{"live_keys":kem.live_keys,"executed_jobs":kem.executed,"rejected_jobs":kem.rejected},"errors":failures}))?;
    require(failures.is_empty(), "load probe failed")
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let result = match Args::read() { Ok(args) => run(args).await, Err(error) => Err(error) };
    if let Err(error) = result { eprintln!("load probe: {error}"); std::process::exit(1); }
}
