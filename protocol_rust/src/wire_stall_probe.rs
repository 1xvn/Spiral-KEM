//! Feature-only bounded bulk transfer with an observed underlying TCP write stall.
#![forbid(unsafe_code)]
use crate::{emit_event, payload};
use serde_json::{json, Value};
use spiral_protocol::{
    channel::{FlowProbe, FlowSnapshot, Session},
    transport::{WireProbe, WireSnapshot},
    Error, Result,
};
use std::{
    io::{BufRead, BufReader, Read},
    sync::{atomic::{AtomicUsize, Ordering}, Arc},
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

const BASELINE: usize = 3;
const MESSAGES: usize = 1024;
const BULK: usize = MESSAGES - BASELINE;
const PAYLOAD: usize = 16384;
const GO: &[u8] = b"wire-stall-go";
const COMPLETE: &[u8] = b"wire-stall-complete";
const STABLE_FOR: Duration = Duration::from_millis(200);

struct Context {
    case: String,
    sid: String,
    binding: String,
    transcript: String,
}
impl Context {
    fn new(case: &str, sid: [u8; 16], binding: [u8; 32], transcript: [u8; 32]) -> Self {
        Self { case: case.to_owned(), sid: hex::encode(sid),
            binding: hex::encode(binding), transcript: hex::encode(transcript) }
    }
    fn event(&self, name: &str, role: &str) -> Value {
        json!({"event":name,"role":role,"case":self.case,"session_id":self.sid,
               "binding_hash":self.binding,"transcript_hash":self.transcript})
    }
    fn ready(&self, role: &str) -> Result<()> {
        let mut event = self.event("wire_ready", role);
        event["baseline_echoes"] = json!(BASELINE);
        event["payload_bytes"] = json!(PAYLOAD);
        event["bulk_messages"] = json!(BULK);
        emit_event(event)
    }
    fn report(&self) -> Value {
        json!({"session_id":self.sid,"binding_hash":self.binding,
            "transcript_hash":self.transcript,"messages":MESSAGES,"payload_bytes":PAYLOAD,
            "baseline_echoes":BASELINE,"bulk_messages":BULK,"authenticated_close":true,
            "wire_stall_case":self.case})
    }
}

fn flow_json(s: &FlowSnapshot) -> Value {
    json!({"allocated_buffers":s.allocated_buffers,"free_buffers":s.free_buffers,
        "in_use_buffers":s.in_use_buffers,"buffer_limit":s.buffer_limit,
        "buffer_capacity_bytes":s.buffer_capacity_bytes,"buffer_waiters":s.buffer_waiters,
        "active_sends":s.active_sends,"send_slot_waiters":s.send_slot_waiters,
        "send_slots_capacity":s.send_slots_capacity,"send_slots_in_use":s.send_slots_in_use,
        "send_channel_closed":s.send_channel_closed,"receive_queue_length":s.receive_queue_length,
        "receive_queue_capacity":s.receive_queue_capacity,
        "receive_delivery_waiters":s.receive_delivery_waiters,
        "reader_done":s.reader_done,"writer_done":s.writer_done,
        "state":s.state,"close_reason":s.close_reason})
}

fn wire_json(s: &WireSnapshot) -> Value {
    json!({"write_pending":s.write_pending,"write_pending_polls":s.write_pending_polls,
        "bytes_written":s.bytes_written,"transport_dropped":s.transport_dropped})
}

fn drained(s: &FlowSnapshot) -> bool {
    s.reader_done && s.writer_done && s.free_buffers == s.allocated_buffers
        && s.in_use_buffers == 0 && s.active_sends == 0 && s.buffer_waiters == 0
        && s.send_slot_waiters == 0 && s.send_slots_in_use.unwrap_or(0) == 0
        && s.receive_delivery_waiters == 0
}

async fn cleanup(flow: &FlowProbe, wire: &WireProbe, context: &Context, role: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let (snapshot, wire_snapshot, complete) = loop {
        let snapshot = flow.snapshot()?;
        let wire_snapshot = wire.snapshot();
        let complete = drained(&snapshot) && wire_snapshot.transport_dropped && !wire_snapshot.write_pending;
        if complete || Instant::now() >= deadline { break (snapshot, wire_snapshot, complete); }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let mut event = context.event("flow_cleanup", role);
    event["drained"] = json!(complete);
    event["snapshot"] = flow_json(&snapshot);
    event["wire_snapshot"] = wire_json(&wire_snapshot);
    emit_event(event)?;
    if complete { Ok(()) } else { Err(Error::Internal) }
}

async fn operator_go() -> Result<()> {
    let task = tokio::task::spawn_blocking(|| {
        // A fixed short line is a test-control barrier, not a protocol message.
        // The owning controller closes this pipe immediately after writing GO.
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin.lock().take(8));
        let mut line = String::with_capacity(8);
        reader.read_line(&mut line)?;
        if line.as_bytes() == b"GO\n" { Ok(()) } else { Err(Error::Input) }
    });
    tokio::time::timeout(Duration::from_secs(10), task).await?
        .map_err(|_| Error::Internal)?
}

pub async fn client(mut session: Session, sid: [u8; 16], binding: [u8; 32],
                    transcript: [u8; 32], case: &str) -> Result<Value> {
    let context = Context::new(case, sid, binding, transcript);
    let flow = session.flow_probe();
    let wire = session.wire_probe();
    let result = client_inner(&mut session, &context).await;
    drop(session);
    cleanup(&flow, &wire, &context, "client").await?;
    result
}

async fn client_inner(session: &mut Session, context: &Context) -> Result<Value> {
    for id in 0..BASELINE {
        let expected = payload(id, PAYLOAD);
        session.send(&expected).await?;
        let received = session.receive().await?;
        if received.as_bytes() != expected { return Err(Error::Authentication); }
        drop(received);
    }
    context.ready("client")?;
    operator_go().await?;
    session.send(GO).await?;
    for id in BASELINE..MESSAGES {
        let received = match session.receive().await {
            Ok(received) => received,
            Err(error) => {
                if context.case == "timeout" {
                    let mut event = context.event("client_wait_failed", "client");
                    event["error"] = json!(format!("{error:?}"));
                    event["verified_bulk"] = json!(id - BASELINE);
                    emit_event(event)?;
                }
                return Err(error);
            }
        };
        if received.as_bytes() != payload(id, PAYLOAD) { return Err(Error::Authentication); }
        drop(received);
    }
    if context.case != "release" { return Err(Error::Internal); }
    let mut event = context.event("bulk_complete", "client");
    event["verified_bulk"] = json!(BULK);
    emit_event(event)?;
    session.send(COMPLETE).await?;
    session.close().await?;
    Ok(json!({"baseline_echoes":BASELINE,"bulk_messages":BULK,"verified_bulk":BULK,
        "authenticated_close":true}))
}

pub async fn server(mut session: Session, sid: [u8; 16], binding: [u8; 32],
                    transcript: [u8; 32], case: &str) -> Result<Value> {
    let context = Context::new(case, sid, binding, transcript);
    let flow = session.flow_probe();
    let wire = session.wire_probe();
    let mut tasks = JoinSet::new();
    let result = server_inner(&mut session, &wire, &context, &mut tasks).await;
    // Joining aborted producers also releases their Sender clones and buffers.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(session);
    cleanup(&flow, &wire, &context, "server").await?;
    result
}

async fn server_inner(session: &mut Session, wire: &WireProbe, context: &Context,
                      tasks: &mut JoinSet<Result<usize>>) -> Result<Value> {
    for id in 0..BASELINE {
        let value = session.receive().await?;
        if value.as_bytes() != payload(id, PAYLOAD) { return Err(Error::Authentication); }
        session.send(value.as_bytes()).await?;
        drop(value);
    }
    context.ready("server")?;
    let go = session.receive().await?;
    if go.as_bytes() != GO { return Err(Error::Authentication); }
    drop(go);
    let baseline_pending_polls = wire.snapshot().write_pending_polls;
    let mut event = context.event("bulk_started", "server");
    event["baseline_pending_polls"] = json!(baseline_pending_polls);
    event["bulk_messages"] = json!(BULK);
    event["payload_bytes"] = json!(PAYLOAD);
    emit_event(event)?;
    let completed = Arc::new(AtomicUsize::new(0));
    let producer_count = completed.clone();
    let sender = session.sender();
    tasks.spawn(async move {
        for id in BASELINE..MESSAGES {
            sender.send(&payload(id, PAYLOAD)).await?;
            producer_count.fetch_add(1, Ordering::Release);
        }
        Ok(BULK)
    });
    let observation_deadline = Instant::now() + Duration::from_secs(15);
    let mut stable = None;
    loop {
        if let Some(result) = tasks.try_join_next() {
            return match result.map_err(|_| Error::Internal)? {
                Ok(_) => Err(Error::Internal), // A completed transfer is not a stall.
                Err(error) => Err(error),
            };
        }
        let snapshot = session.flow_snapshot()?;
        let wire_snapshot = wire.snapshot();
        if snapshot.state == 0 && wire_snapshot.write_pending
            && wire_snapshot.write_pending_polls > baseline_pending_polls
            && !wire_snapshot.transport_dropped && completed.load(Ordering::Acquire) < BULK
        {
            let (bytes, since, initial) = stable.get_or_insert_with(||
                (wire_snapshot.bytes_written, Instant::now(), wire_snapshot));
            if *bytes != wire_snapshot.bytes_written {
                *bytes = wire_snapshot.bytes_written;
                *since = Instant::now();
                *initial = wire_snapshot;
            }
            if since.elapsed() >= STABLE_FOR {
                let mut event = context.event("wire_stalled", "server");
                event["stable_start_wire_snapshot"] = wire_json(initial);
                event["wire_snapshot"] = wire_json(&wire_snapshot);
                event["snapshot"] = flow_json(&snapshot);
                event["stable_ms"] = json!(since.elapsed().as_secs_f64() * 1000.);
                event["baseline_pending_polls"] = json!(baseline_pending_polls);
                event["completed_bulk"] = json!(completed.load(Ordering::Acquire));
                event["bulk_messages"] = json!(BULK);
                event["payload_bytes"] = json!(PAYLOAD);
                emit_event(event)?;
                break;
            }
        } else { stable = None; }
        if Instant::now() >= observation_deadline { return Err(Error::Internal); }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stalled_at = Instant::now();
    let producer_result = tokio::time::timeout(Duration::from_secs(75), tasks.join_next()).await?
        .ok_or(Error::Internal)?.map_err(|_| Error::Internal)?;
    if context.case == "timeout" {
        let error = match producer_result {
            Err(error @ (Error::Deadline | Error::Closed)) => error,
            _ => return Err(Error::Internal),
        };
        let elapsed_ms = stalled_at.elapsed().as_secs_f64() * 1000.;
        let snapshot = session.flow_snapshot()?;
        if elapsed_ms < 55_000. || (error != Error::Deadline && snapshot.close_reason != 1)
            || completed.load(Ordering::Acquire) >= BULK
        { return Err(Error::Internal); }
        let mut event = context.event("wire_timeout", "server");
        event["elapsed_ms"] = json!(elapsed_ms);
        event["send_error"] = json!(format!("{error:?}"));
        event["local_close_reason"] = json!(snapshot.close_reason);
        event["completed_bulk"] = json!(completed.load(Ordering::Acquire));
        event["snapshot"] = flow_json(&snapshot);
        event["wire_snapshot"] = wire_json(&wire.snapshot());
        emit_event(event)?;
        return Err(error);
    }
    if context.case != "release" || producer_result? != BULK { return Err(Error::Internal); }
    let mut event = context.event("bulk_complete", "server");
    event["completed_bulk"] = json!(BULK);
    emit_event(event)?;
    let complete = session.receive().await?;
    if complete.as_bytes() != COMPLETE { return Err(Error::Authentication); }
    drop(complete);
    session.close().await?;
    Ok(context.report())
}
