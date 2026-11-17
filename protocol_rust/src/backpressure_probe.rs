//! Opt-in loopback scenarios. Pool and queue limits remain production values.
#![forbid(unsafe_code)]
use crate::{emit_event, payload};
use serde_json::{json, Value};
use spiral_protocol::{
    channel::{FlowProbe, FlowSnapshot, Session},
    Error, Result,
};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

const SEEDS: usize = 18;
const REQUESTS: usize = 10;
const PAYLOAD_BYTES: usize = 1024;
const STABLE_FOR: Duration = Duration::from_millis(200);
const OBSERVE_FOR: Duration = Duration::from_secs(3);

struct Context {
    case: String,
    sid: String,
    binding: String,
    transcript: String,
}
impl Context {
    fn new(case: &str, sid: [u8; 16], binding: [u8; 32], transcript: [u8; 32]) -> Self {
        Self {
            case: case.to_owned(),
            sid: hex::encode(sid),
            binding: hex::encode(binding),
            transcript: hex::encode(transcript),
        }
    }
    fn event(&self, event: &str, role: &str) -> Value {
        json!({"event":event,"role":role,"case":self.case,"session_id":self.sid,
            "binding_hash":self.binding,"transcript_hash":self.transcript})
    }
}

fn snapshot_json(s: &FlowSnapshot) -> Value {
    json!({
        "allocated_buffers":s.allocated_buffers,"free_buffers":s.free_buffers,
        "in_use_buffers":s.in_use_buffers,"buffer_limit":s.buffer_limit,
        "buffer_capacity_bytes":s.buffer_capacity_bytes,"buffer_waiters":s.buffer_waiters,
        "active_sends":s.active_sends,"send_slot_waiters":s.send_slot_waiters,
        "send_slots_capacity":s.send_slots_capacity,"send_slots_in_use":s.send_slots_in_use,
        "send_channel_closed":s.send_channel_closed,
        "receive_queue_length":s.receive_queue_length,
        "receive_queue_capacity":s.receive_queue_capacity,
        "receive_delivery_waiters":s.receive_delivery_waiters,
        "reader_done":s.reader_done,"writer_done":s.writer_done,
        "state":s.state,"close_reason":s.close_reason,
    })
}

async fn stable_snapshot(
    session: &Session,
    condition: impl Fn(&FlowSnapshot) -> bool,
) -> Result<(FlowSnapshot, f64)> {
    let end = Instant::now() + OBSERVE_FOR;
    let mut stable_since = None;
    loop {
        let snapshot = session.flow_snapshot()?;
        if condition(&snapshot) {
            let since = stable_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= STABLE_FOR {
                return Ok((snapshot, since.elapsed().as_secs_f64() * 1000.));
            }
        } else {
            stable_since = None;
        }
        if Instant::now() >= end {
            return Err(Error::Internal);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn no_producers(s: &FlowSnapshot) -> bool {
    s.active_sends == 0
        && s.buffer_waiters == 0
        && s.send_slot_waiters == 0
        && s.send_slots_in_use.unwrap_or(0) == 0
}

async fn cleanup(probe: &FlowProbe, context: &Context, role: &str) -> Result<FlowSnapshot> {
    let end = Instant::now() + OBSERVE_FOR;
    let (snapshot, drained) = loop {
        let snapshot = probe.snapshot()?;
        let drained = snapshot.reader_done
            && snapshot.writer_done
            && snapshot.free_buffers == snapshot.allocated_buffers
            && snapshot.in_use_buffers == 0
            && snapshot.receive_delivery_waiters == 0
            && no_producers(&snapshot);
        if drained || Instant::now() >= end {
            break (snapshot, drained);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let mut event = context.event("flow_cleanup", role);
    event["drained"] = json!(drained);
    event["snapshot"] = snapshot_json(&snapshot);
    emit_event(event)?;
    if !drained {
        return Err(Error::Internal);
    }
    Ok(snapshot)
}

pub async fn server(
    mut session: Session,
    sid: [u8; 16],
    binding: [u8; 32],
    transcript: [u8; 32],
    case: &str,
) -> Result<Value> {
    let context = Context::new(case, sid, binding, transcript);
    let probe = session.flow_probe();
    let result = server_inner(&mut session, &context).await;
    drop(session);
    cleanup(&probe, &context, "server").await?;
    result
}

async fn server_inner(session: &mut Session, context: &Context) -> Result<Value> {
    for id in 0..SEEDS {
        session.send(&payload(id, PAYLOAD_BYTES)).await?;
    }
    let mut event = context.event("seed_sent", "server");
    event["sent_messages"] = json!(SEEDS);
    event["payload_bytes"] = json!(PAYLOAD_BYTES);
    emit_event(event)?;
    let mut seen = [false; REQUESTS];
    for _ in 0..REQUESTS {
        let value = session.receive().await?;
        let id = request_id(value.as_bytes())?;
        if seen[id] {
            return Err(Error::Authentication);
        }
        seen[id] = true;
        session.send(value.as_bytes()).await?;
    }
    session.close().await?;
    Ok(json!({"session_id":context.sid,"binding_hash":context.binding,
        "transcript_hash":context.transcript,"messages":REQUESTS,"payload_bytes":PAYLOAD_BYTES,
        "authenticated_close":true,"backpressure_case":context.case}))
}

fn request_id(bytes: &[u8]) -> Result<usize> {
    if bytes.len() != PAYLOAD_BYTES {
        return Err(Error::Authentication);
    }
    let wire_id = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| Error::Authentication)?);
    if !(100..100 + REQUESTS as u64).contains(&wire_id) {
        return Err(Error::Authentication);
    }
    let id = (wire_id - 100) as usize;
    if bytes != payload(100 + id, PAYLOAD_BYTES) {
        return Err(Error::Authentication);
    }
    Ok(id)
}

fn producers(session: &Session) -> JoinSet<Result<()>> {
    let mut tasks = JoinSet::new();
    for id in 100..100 + REQUESTS {
        let sender = session.sender();
        tasks.spawn(async move { sender.send(&payload(id, PAYLOAD_BYTES)).await });
    }
    tasks
}

async fn join_success(tasks: &mut JoinSet<Result<()>>) -> Result<usize> {
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        result.map_err(|_| Error::Internal)??;
        completed += 1;
    }
    if completed != REQUESTS {
        return Err(Error::Internal);
    }
    Ok(completed)
}

async fn receive_echoes(session: &mut Session) -> Result<usize> {
    let mut seen = [false; REQUESTS];
    for _ in 0..REQUESTS {
        let value = session.receive().await?;
        let id = request_id(value.as_bytes())?;
        if seen[id] {
            return Err(Error::Authentication);
        }
        seen[id] = true;
        // Returning each buffer here lets the remaining producers and reader progress.
        drop(value);
    }
    Ok(REQUESTS)
}

enum Outcome {
    Passed(Value),
    Expired {
        elapsed_ms: f64,
        deadline_errors: usize,
        closed_errors: usize,
    },
}

pub async fn client(
    mut session: Session,
    sid: [u8; 16],
    binding: [u8; 32],
    transcript: [u8; 32],
    case: &str,
) -> Result<Value> {
    let context = Context::new(case, sid, binding, transcript);
    let probe = session.flow_probe();
    let result = client_inner(&mut session, &context).await;
    drop(session);
    let snapshot = cleanup(&probe, &context, "client").await?;
    match result? {
        Outcome::Passed(report) => {
            if snapshot.allocated_buffers != SEEDS || snapshot.free_buffers != SEEDS {
                return Err(Error::Internal);
            }
            Ok(report)
        }
        Outcome::Expired { elapsed_ms, deadline_errors, closed_errors } => {
            let mut event = context.event("pressure_timeout", "client");
            event["elapsed_ms"] = json!(elapsed_ms);
            event["deadline_errors"] = json!(deadline_errors);
            event["closed_errors"] = json!(closed_errors);
            event["completed_sends"] = json!(0);
            event["snapshot"] = snapshot_json(&snapshot);
            emit_event(event)?;
            Err(Error::Deadline)
        }
    }
}

async fn client_inner(session: &mut Session, context: &Context) -> Result<Outcome> {
    // Observe actual delivery pressure before the application consumes any DATA.
    let (snapshot, stable_ms) = stable_snapshot(session, |s| {
        s.receive_queue_length == Some(8) && s.receive_delivery_waiters == 1
    }).await?;
    let mut event = context.event("receiver_queue_saturated", "client");
    event["held_buffers"] = json!(0);
    event["queued_messages"] = json!(8);
    event["stable_ms"] = json!(stable_ms);
    event["snapshot"] = snapshot_json(&snapshot);
    emit_event(event)?;

    let mut held = Vec::with_capacity(SEEDS);
    for id in 0..SEEDS {
        let value = session.receive().await?;
        if value.as_bytes() != payload(id, PAYLOAD_BYTES) {
            return Err(Error::Authentication);
        }
        held.push(value);
    }
    let mut tasks = producers(session);
    let (snapshot, stable_ms) = stable_snapshot(session, |s| {
        s.allocated_buffers == SEEDS && s.free_buffers == 0 && s.in_use_buffers == SEEDS
            && s.buffer_waiters == 8 && s.send_slot_waiters == 2
            && s.active_sends == REQUESTS && s.send_slots_in_use == Some(8)
    }).await?;
    if tasks.try_join_next().is_some() || tasks.len() != REQUESTS {
        return Err(Error::Internal);
    }
    let mut event = context.event("pressure_saturated", "client");
    event["held_buffers"] = json!(held.len());
    event["producer_tasks"] = json!(tasks.len());
    event["completed_sends"] = json!(0);
    event["stable_ms"] = json!(stable_ms);
    event["snapshot"] = snapshot_json(&snapshot);
    emit_event(event)?;
    let pressure_started = Instant::now();

    match context.case.as_str() {
        "release" => {
            drop(held.pop().ok_or(Error::Internal)?);
            let (verified_echoes, completed_sends) = tokio::try_join!(
                receive_echoes(session), join_success(&mut tasks)
            )?;
            let mut event = context.event("pressure_released", "client");
            event["released_buffers"] = json!(1);
            event["held_buffers"] = json!(held.len());
            event["completed_sends"] = json!(completed_sends);
            event["verified_echoes"] = json!(verified_echoes);
            event["snapshot"] = snapshot_json(&session.flow_snapshot()?);
            emit_event(event)?;
        }
        "cancel" => {
            tasks.abort_all();
            let mut cancelled = 0;
            while let Some(result) = tasks.join_next().await {
                match result {
                    Err(error) if error.is_cancelled() => cancelled += 1,
                    _ => return Err(Error::Internal),
                }
            }
            if cancelled != REQUESTS {
                return Err(Error::Internal);
            }
            let (snapshot, _) = stable_snapshot(session, no_producers).await?;
            let mut event = context.event("producer_cancelled", "client");
            event["cancelled_sends"] = json!(cancelled);
            event["held_buffers"] = json!(held.len());
            event["completed_sends"] = json!(0);
            event["snapshot"] = snapshot_json(&snapshot);
            emit_event(event)?;
            held.clear();
            tasks = producers(session);
            tokio::try_join!(receive_echoes(session), join_success(&mut tasks))?;
        }
        "timeout" => {
            // This watchdog only detects a stuck probe. The session's existing
            // 60-second idle deadline must wake the producers first.
            let (deadline_errors, closed_errors) = tokio::time::timeout(
                Duration::from_secs(70),
                async {
                    let mut deadline_errors = 0;
                    let mut closed_errors = 0;
                    while let Some(result) = tasks.join_next().await {
                        match result.map_err(|_| Error::Internal)? {
                            Err(Error::Deadline) => deadline_errors += 1,
                            Err(Error::Closed) => closed_errors += 1,
                            _ => return Err(Error::Internal),
                        }
                    }
                    Ok::<_, Error>((deadline_errors, closed_errors))
                },
            ).await??;
            let elapsed_ms = pressure_started.elapsed().as_secs_f64() * 1000.;
            let snapshot = session.flow_snapshot()?;
            if elapsed_ms < 55_000.
                || deadline_errors + closed_errors != REQUESTS
                || !no_producers(&snapshot)
            {
                return Err(Error::Internal);
            }
            // Retained plaintext is released before the outer cleanup observes
            // both I/O tasks and the entire pool returning to quiescence.
            drop(held);
            return Ok(Outcome::Expired { elapsed_ms, deadline_errors, closed_errors });
        }
        _ => return Err(Error::Input),
    }
    drop(held);
    session.close().await?;
    Ok(Outcome::Passed(json!({"completed_sends":REQUESTS,"verified_echoes":REQUESTS,
        "seed_messages":SEEDS,"authenticated_close":true})))
}
