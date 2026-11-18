//! Feature-only application workload for one shared admission gate and worker pool.
use super::{emit_event, wire_stall_probe};
use serde_json::{json, Value};
use spiral_protocol::{
    admission::Admission, channel::{FlowProbe, Session}, transport::WireProbe,
    worker::KemPool, Error, Result,
};
use std::{io::Read, sync::{Mutex, OnceLock}, time::Duration};
use tokio::sync::Notify;

type Ids = ([u8; 16], [u8; 32], [u8; 32]);
const MAX_ROUNDS: u32 = 512;

fn event(kind: &str, lane: u8, ids: &Ids) -> Value {
    json!({"event":kind,"lane":lane,"session_id":hex::encode(ids.0),
        "binding_hash":hex::encode(ids.1),"transcript_hash":hex::encode(ids.2)})
}

fn challenge(lane: u8, sequence: u32, ids: &Ids) -> [u8; 1024] {
    let mut bytes = [lane; 1024];
    bytes[1..5].copy_from_slice(&sequence.to_be_bytes());
    bytes[5..21].copy_from_slice(&ids.0);
    bytes[21..53].copy_from_slice(&ids.1);
    bytes[53..85].copy_from_slice(&ids.2);
    bytes
}

pub async fn client(mut session: Session, ids: Ids, lane: u8, case: &str) -> Result<Value> {
    session.send(&[lane]).await?;
    if lane == 0 {
        return wire_stall_probe::client(session, ids.0, ids.1, ids.2, case).await;
    }
    emit_event(event("lane_ready", lane, &ids))?;
    for seq in 0..MAX_ROUNDS {
        let cmd = tokio::task::spawn_blocking(|| {
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte)?;
            Ok::<_, Error>(byte[0])
        }).await.map_err(|_| Error::Internal)??;
        if cmd == b'C' {
            if seq == 0 { return Err(Error::Input); }
            session.send(b"finish").await?;
            session.close().await?;
            let mut report = event("lane_closed", lane, &ids);
            report["verified"] = json!(seq);
            report["authenticated_close"] = json!(true);
            return Ok(report);
        }
        if cmd != b'E' { return Err(Error::Input); }
        let expected = challenge(lane, seq, &ids);
        session.send(&expected).await?;
        if session.receive().await?.as_bytes() != expected { return Err(Error::Authentication); }
        let mut report = event("verified", lane, &ids);
        report["sequence"] = json!(seq);
        emit_event(report)?;
    }
    Err(Error::Input)
}

pub struct State {
    case: String,
    lanes: Mutex<[bool; 5]>,
    stalled: OnceLock<(WireProbe, FlowProbe)>,
    pub reclaimed: Notify,
}

impl State {
    pub fn new(case: &str) -> Self {
        Self { case: case.to_owned(), lanes: Mutex::new([false; 5]),
            stalled: OnceLock::new(), reclaimed: Notify::new() }
    }

    pub async fn serve(&self, mut session: Session, ids: Ids, gate: &Admission, pool: &KemPool) -> Result<Value> {
        let tag = session.receive().await?;
        let [lane] = *tag.as_bytes() else { return Err(Error::Input); };
        drop(tag);
        {
            let mut lanes = self.lanes.lock().map_err(|_| Error::Internal)?;
            let seen = lanes.get_mut(lane as usize).ok_or(Error::Input)?;
            if *seen { return Err(Error::Input); }
            *seen = true;
        }
        emit_event(event("lane_ready", lane, &ids))?;
        if lane == 0 {
            self.stalled.set((session.wire_probe(), session.flow_probe())).map_err(|_| Error::Internal)?;
            let result = wire_stall_probe::server(session, ids.0, ids.1, ids.2, &self.case).await;
            match (&*self.case, result) {
                ("release", Ok(_)) | ("timeout", Err(Error::Closed | Error::Deadline)) => (),
                (_, Err(e)) => return Err(e),
                _ => return Err(Error::Internal),
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                while gate.counts()? != (3, 0) || pool.metrics().live_keys != 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok::<_, Error>(())
            }).await??;
            let mut report = event("reclaimed", lane, &ids);
            let (active, pending) = gate.counts()?;
            report["active"] = json!(active);
            report["pending"] = json!(pending);
            report["live_keys"] = json!(pool.metrics().live_keys);
            emit_event(report.clone())?;
            self.reclaimed.notify_one();
            return Ok(report);
        }
        for seq in 0..MAX_ROUNDS {
            let msg = session.receive().await?;
            if msg.as_bytes() == b"finish" && seq > 0 {
                drop(msg);
                session.close().await?;
                let mut report = event("lane_closed", lane, &ids);
                report["verified"] = json!(seq);
                report["authenticated_close"] = json!(true);
                return Ok(report);
            }
            if msg.as_bytes() != challenge(lane, seq, &ids) { return Err(Error::Authentication); }
            session.send(msg.as_bytes()).await?;
            let mut report = event("echoed", lane, &ids);
            report["sequence"] = json!(seq);
            let (active, pending) = gate.counts()?;
            report["active"] = json!(active);
            report["pending"] = json!(pending);
            if let Some((wire, flow)) = self.stalled.get() {
                let w = wire.snapshot();
                report["stalled_bytes"] = json!(w.bytes_written);
                report["stalled_pending"] = json!(w.write_pending);
                report["stalled_state"] = json!(flow.snapshot()?.state);
            }
            emit_event(report)?;
        }
        Err(Error::Input)
    }
}
