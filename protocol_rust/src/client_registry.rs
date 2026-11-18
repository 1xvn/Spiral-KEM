//! Immutable lab grants scoped by configured DNS name, service and authenticated leaf DER.
use crate::emit_event;
use serde_json::{json, Value};
use spiral_protocol::{channel::Session, Error, Result};
use std::{collections::HashMap, fs::File, io::Read, path::Path};

pub struct Registry(HashMap<[u8; 32], bool>);

impl Registry {
    pub fn load(path: &Path, name: &str, service: &str) -> Result<Self> {
        let mut text = String::new();
        File::open(path)?.take(65537).read_to_string(&mut text)?;
        if text.len() > 65536 { return Err(Error::Input); }
        let mut grants = HashMap::new();
        for line in text.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            let [host, audience, digest, role] = fields.as_slice() else { return Err(Error::Input); };
            let mut fingerprint = [0; 32];
            hex::decode_to_slice(digest, &mut fingerprint).map_err(|_| Error::Input)?;
            let active = match *role {
                "status-reader" => true,
                "revoked" => false,
                _ => return Err(Error::Input),
            };
            if *host == name && *audience == service && grants.insert(fingerprint, active).is_some() {
                return Err(Error::Input);
            }
        }
        Ok(Self(grants))
    }

    pub fn admit(&self, fingerprint: &[u8; 32]) -> Result<()> {
        if self.0.get(fingerprint) != Some(&true) {
            emit_event(json!({"event":"registry_denied"}))?;
            return Err(Error::Authentication);
        }
        emit_event(json!({"event":"registry_admitted"}))
    }
}

pub async fn serve(mut session: Session, messages: usize) -> Result<Value> {
    for _ in 0..messages {
        let request = session.receive().await?;
        if request.as_bytes() != b"READ /status" {
            emit_event(json!({"event":"operation_denied"}))?;
            return Err(Error::Authentication);
        }
        session.send(b"lab-ready").await?;
        emit_event(json!({"event":"status_read"}))?;
    }
    session.close().await?;
    Ok(json!({"messages": messages, "authenticated_close":true}))
}
