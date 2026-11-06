#![forbid(unsafe_code)]
use crate::{
    schedule::{self, SessionKeys},
    secret::Secret,
    transport::{FrameIo, Transport},
    wire::{self, Header, HEADER, SUITE},
    worker::KemPool,
    Error, Result,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct Pin {
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub revoked: bool,
}
pub fn validate_identity(name: &str, service: &str) -> Result<()> {
    let label = |s: &str| {
        !s.is_empty()
            && s.len() <= 63
            && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || !name.split('.').all(label)
        || name.parse::<IpAddr>().is_ok()
    {
        return Err(Error::Input);
    }
    if service.is_empty()
        || service.len() > 64
        || !service.as_bytes()[0].is_ascii_alphanumeric()
        || !service
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._/-".contains(&b))
    {
        return Err(Error::Input);
    }
    Ok(())
}
fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0; N];
    getrandom::getrandom(&mut b).map_err(|_| Error::Crypto)?;
    Ok(b)
}
fn v32(v: &[u8]) -> Vec<u8> {
    let mut r = (v.len() as u32).to_be_bytes().to_vec();
    r.extend_from_slice(v);
    r
}
fn signature_input(ch: &[u8], sh_without_signature: &[u8]) -> Vec<u8> {
    let mut b = schedule::domain(b"server-signature");
    b.extend_from_slice(&v32(ch));
    b.extend_from_slice(&v32(sh_without_signature));
    b
}
pub(crate) fn hello(
    name: &str,
    service: &str,
    binding: [u8; 32],
    random: [u8; 32],
) -> Result<Vec<u8>> {
    validate_identity(name, service)?;
    let mut p = random.to_vec();
    p.extend_from_slice(&binding);
    p.extend_from_slice(&[1, 0, 1, 1, 0xf0, 1]);
    p.extend_from_slice(&(name.len() as u16).to_be_bytes());
    p.extend_from_slice(name.as_bytes());
    p.push(service.len() as u8);
    p.extend_from_slice(service.as_bytes());
    Ok(p)
}
pub(crate) fn parse_hello(p: &[u8]) -> Result<(&str, &str)> {
    if !(75..=418).contains(&p.len()) {
        return Err(Error::Input);
    }
    let mut i = 64;
    fn take<'a>(p: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8]> {
        let end = i.checked_add(n).ok_or(Error::Input)?;
        let s = p.get(*i..end).ok_or(Error::Input)?;
        *i = end;
        Ok(s)
    }
    for required in [1, SUITE] {
        let n = take(p, &mut i, 1)?[0] as usize;
        if !(1..=8).contains(&n) {
            return Err(Error::Input);
        }
        let mut last = 0;
        let mut found = false;
        for _ in 0..n {
            let v = u16::from_be_bytes(take(p, &mut i, 2)?.try_into().unwrap());
            if v <= last {
                return Err(Error::Input);
            }
            last = v;
            found |= v == required;
        }
        if !found {
            return Err(Error::Input);
        }
    }
    let n = u16::from_be_bytes(take(p, &mut i, 2)?.try_into().unwrap()) as usize;
    let name = std::str::from_utf8(take(p, &mut i, n)?).map_err(|_| Error::Input)?;
    let n = take(p, &mut i, 1)?[0] as usize;
    let service = std::str::from_utf8(take(p, &mut i, n)?).map_err(|_| Error::Input)?;
    if i != p.len() {
        return Err(Error::Input);
    }
    validate_identity(name, service)?;
    Ok((name, service))
}
static LIVE: OnceLock<Mutex<HashSet<[u8; 16]>>> = OnceLock::new();
pub(crate) struct SessionId([u8; 16]);
impl SessionId {
    fn reserve() -> Result<Self> {
        let mut ids = LIVE
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| Error::Internal)?;
        for _ in 0..16 {
            let id = random()?;
            if id != [0; 16] && ids.insert(id) {
                return Ok(Self(id));
            }
        }
        Err(Error::Crypto)
    }
}
impl Drop for SessionId {
    fn drop(&mut self) {
        if let Some(ids) = LIVE.get() {
            if let Ok(mut ids) = ids.lock() {
                ids.remove(&self.0);
                if ids.is_empty() {
                    *ids = HashSet::new();
                }
            }
        }
    }
}

/// A transport/key pair constructible only after authenticating Finished.
pub struct Established {
    io: Transport,
    keys: SessionKeys,
    role: u8,
    lease: Option<crate::admission::Lease>,
    id: Option<SessionId>,
}
#[derive(Clone, Copy, Debug)]
pub struct SessionInfo {
    pub sid: [u8; 16],
    pub transcript: [u8; 32],
    pub binding_hash: [u8; 32],
}
impl Established {
    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            sid: self.keys.sid,
            transcript: self.keys.transcript,
            binding_hash: self.io.binding_hash(),
        }
    }
    pub fn start(self) -> Result<crate::channel::Session> {
        crate::channel::Session::start(self.io, self.keys, self.role, self.lease, self.id)
    }
}
pub async fn client(
    io: Transport,
    name: &str,
    service: &str,
    pin: Pin,
    pool: &KemPool,
) -> Result<Established> {
    let mut io = io;
    let keys = client_inner(&mut io, name, service, &pin, pool).await?;
    Ok(Established {
        io,
        keys,
        role: 0,
        lease: None,
        id: None,
    })
}
pub async fn server(
    io: Transport,
    name: &str,
    service: &str,
    signing: Arc<SigningKey>,
    pool: &KemPool,
    lease: crate::admission::Lease,
) -> Result<Established> {
    let mut io = io;
    let (keys, id) = server_inner(&mut io, name, service, &signing, pool).await?;
    Ok(Established {
        io,
        keys,
        role: 1,
        lease: Some(lease.established()?),
        id: Some(id),
    })
}
async fn client_inner<I: FrameIo>(
    io: &mut I,
    name: &str,
    service: &str,
    pin: &Pin,
    pool: &KemPool,
) -> Result<SessionKeys> {
    validate_identity(name, service)?;
    if io.name() != name {
        return Err(Error::Authentication);
    }
    let end = io.deadline().min(Instant::now() + Duration::from_secs(10));
    let ch = wire::frame(
        1,
        0,
        [0; 16],
        0,
        &hello(name, service, io.binding(), random()?)?,
    )?;
    io.send(&ch, end).await?;
    let sh = io.recv(2, 1, None, 0, end).await?;
    let (h, b) = wire::parse(&sh)?;
    h.expect(Some(2), 1, None, 0)?;
    if b[..4] != [0, 1, 0xf0, 1] {
        return Err(Error::Input);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Internal)?
        .as_secs();
    if pin.revoked
        || !(pin.not_before <= now && now < pin.not_after)
        || !equal(&schedule::digest(&pin.public_key), &b[36..68])
    {
        return Err(Error::Authentication);
    }
    let key = VerifyingKey::from_bytes(&pin.public_key).map_err(|_| Error::Authentication)?;
    let signature = Signature::from_slice(&b[876..]).map_err(|_| Error::Authentication)?;
    key.verify_strict(&signature_input(&ch, &sh[..sh.len() - 64]), &signature)
        .map_err(|_| Error::Authentication)?;
    let pk = Box::new(b[68..876].try_into().map_err(|_| Error::Input)?);
    let (ct, ss) = pool.encapsulate(pk, end).await?;
    let ck_head = Header {
        kind: 3,
        role: 0,
        sid: h.sid,
        sequence: 1,
        length: 1192,
    }
    .encode()?;
    let s = schedule::schedule(&ch, &sh, &ck_head, ct.as_slice(), ss)?;
    let mut ck = ck_head.to_vec();
    ck.extend_from_slice(ct.as_slice());
    ck.extend_from_slice(&s.cf);
    io.send(&ck, end).await?;
    let sf = io.recv(4, 1, Some(h.sid), 1, end).await?;
    let h1 = schedule::hash_parts(&[&ch, &sh, &ck, &sf[..HEADER]]);
    let expected = schedule::mac(s.sf.bytes(), &[&schedule::domain(b"server-finished"), &h1]);
    if !equal(&expected, &sf[HEADER..]) {
        return Err(Error::Authentication);
    }
    if Instant::now() >= end {
        return Err(Error::Deadline);
    }
    schedule::finish(s, h.sid, &ch, &sh, &ck, &sf)
}
async fn server_inner<I: FrameIo>(
    io: &mut I,
    name: &str,
    service: &str,
    signing: &SigningKey,
    pool: &KemPool,
) -> Result<(SessionKeys, SessionId)> {
    validate_identity(name, service)?;
    if io.name() != name {
        return Err(Error::Authentication);
    }
    let end = io.deadline().min(Instant::now() + Duration::from_secs(10));
    let ch = io.recv(1, 0, Some([0; 16]), 0, end).await?;
    let (_, p) = wire::parse(&ch)?;
    let (host, purpose) = parse_hello(p)?;
    if host != name || purpose != service || !equal(&p[32..64], &io.binding()) {
        return Err(Error::Authentication);
    }
    let id = SessionId::reserve()?;
    let (pk, lease) = pool.generate(end).await?;
    let auth = signing.verifying_key().to_bytes();
    let mut body = vec![0, 1, 0xf0, 1];
    body.extend_from_slice(&random::<32>()?);
    body.extend_from_slice(&schedule::digest(&auth));
    body.extend_from_slice(pk.as_slice());
    let mut sh = Header {
        kind: 2,
        role: 1,
        sid: id.0,
        sequence: 0,
        length: 940,
    }
    .encode()?
    .to_vec();
    sh.extend_from_slice(&body);
    let sig = signing.sign(&signature_input(&ch, &sh));
    sh.extend_from_slice(&sig.to_bytes());
    io.send(&sh, end).await?;
    let ck_end = end.min(Instant::now() + Duration::from_secs(5));
    let ck = io.recv(3, 0, Some(id.0), 1, ck_end).await?;
    let ct = Box::new(
        ck[HEADER..HEADER + 1160]
            .try_into()
            .map_err(|_| Error::Input)?,
    );
    let ss = pool.decapsulate(lease, ct, ck_end).await?;
    let s = schedule::schedule(&ch, &sh, &ck[..HEADER], &ck[HEADER..HEADER + 1160], ss)?;
    if !equal(&s.cf, &ck[HEADER + 1160..]) {
        return Err(Error::Authentication);
    }
    let sf_head = Header {
        kind: 4,
        role: 1,
        sid: id.0,
        sequence: 1,
        length: 32,
    }
    .encode()?;
    let h1 = schedule::hash_parts(&[&ch, &sh, &ck, &sf_head]);
    let sf_mac = schedule::mac(s.sf.bytes(), &[&schedule::domain(b"server-finished"), &h1]);
    let mut sf = sf_head.to_vec();
    sf.extend_from_slice(&sf_mac);
    io.send(&sf, end).await?;
    if Instant::now() >= end {
        return Err(Error::Deadline);
    }
    let keys = schedule::finish(s, id.0, &ch, &sh, &ck, &sf)?;
    Ok((keys, id))
}

pub fn load_signing_key(path: &std::path::Path) -> Result<Arc<SigningKey>> {
    use std::io::Read;
    let mut key = Secret::<32>::zeros();
    let mut file = std::fs::File::open(path)?;
    file.read_exact(key.bytes_mut())?;
    let mut extra = [0; 1];
    if file.read(&mut extra)? != 0 {
        return Err(Error::Input);
    }
    Ok(Arc::new(SigningKey::from_bytes(key.bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../protocol_v01/tests/fixtures/test_vectors_v0.1.json"
        ))
        .unwrap()
    }
    #[test]
    fn identities_and_hello_grammar() {
        let v = fixture();
        let p = hex::decode(v["frames"]["client_hello"].as_str().unwrap()).unwrap()[40..].to_vec();
        assert_eq!(
            parse_hello(&p).unwrap(),
            ("spiral-lab.example", "spiral-research")
        );
        for offset in [64, 67] {
            for value in 0..=255 {
                if value == 1 {
                    continue;
                }
                let mut bad = p.clone();
                bad[offset] = value;
                assert!(parse_hello(&bad).is_err());
            }
        }
        for n in 0..p.len() {
            assert!(parse_hello(&p[..n]).is_err());
        }
        for host in [
            "",
            "A.example",
            "a..b",
            "-a.example",
            "a-.example",
            "127.0.0.1",
            "a.",
            "é.example",
        ] {
            assert!(validate_identity(host, "service").is_err());
        }
        for s in ["", "UPPER", ".bad", "a b"] {
            assert!(validate_identity("a.example", s).is_err());
        }
    }
    #[test]
    fn original_signature_and_clienthello() {
        let v = fixture();
        let raw = |group: &str, n: &str| hex::decode(v[group][n].as_str().unwrap()).unwrap();
        let ch = raw("frames", "client_hello");
        let sh = raw("frames", "server_hello");
        let input = signature_input(&ch, &sh[..sh.len() - 64]);
        assert_eq!(input, raw("expected", "signature_input"));
        let seed: [u8; 32] = raw("inputs", "server_auth_seed").try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(
            key.sign(&input).to_bytes().as_slice(),
            raw("expected", "server_signature")
        );
        let random = raw("inputs", "client_random").try_into().unwrap();
        let binding = raw("inputs", "synthetic_exporter").try_into().unwrap();
        assert_eq!(
            hello("spiral-lab.example", "spiral-research", binding, random).unwrap(),
            ch[40..]
        );
    }
    struct Script {
        ch: Vec<u8>,
        sh: Option<Vec<u8>>,
        sent: Vec<u8>,
        pool: KemPool,
        bad_finished: Option<usize>,
        bad_ct: bool,
        bind: [u8; 32],
        end: Instant,
    }
    #[async_trait::async_trait]
    impl FrameIo for Script {
        fn binding(&self) -> [u8; 32] {
            self.bind
        }
        fn name(&self) -> &str {
            "spiral-lab.example"
        }
        fn deadline(&self) -> Instant {
            self.end
        }
        async fn send(&mut self, raw: &[u8], _: Instant) -> Result<()> {
            self.sent.push(raw[6]);
            if raw[6] == 2 {
                self.sh = Some(raw.to_vec());
            }
            Ok(())
        }
        async fn recv(
            &mut self,
            kind: u8,
            _: u8,
            _: Option<[u8; 16]>,
            _: u64,
            end: Instant,
        ) -> Result<Vec<u8>> {
            if kind == 1 {
                return Ok(self.ch.clone());
            }
            let sh = self.sh.as_ref().ok_or(Error::Internal)?;
            let (h, p) = wire::parse(sh)?;
            let (ct, ss) = self
                .pool
                .encapsulate(Box::new(p[68..876].try_into().unwrap()), end)
                .await?;
            let head = Header {
                kind: 3,
                role: 0,
                sid: h.sid,
                sequence: 1,
                length: 1192,
            }
            .encode()?;
            let s = schedule::schedule(&self.ch, sh, &head, ct.as_slice(), ss)?;
            let mut ck = head.to_vec();
            ck.extend_from_slice(ct.as_slice());
            ck.extend_from_slice(&s.cf);
            if let Some(i) = self.bad_finished {
                ck[1200 + i] ^= 1;
            }
            if self.bad_ct {
                let x = u16::from(ck[48]) | ((u16::from(ck[49]) & 15) << 8);
                let y = (x + 1) % 3329;
                ck[48] = y as u8;
                ck[49] = (ck[49] & 0xf0) | ((y >> 8) as u8);
            }
            Ok(ck)
        }
    }
    fn script(pool: &KemPool) -> Script {
        let bind = [19; 32];
        let ch = wire::frame(
            1,
            0,
            [0; 16],
            0,
            &hello("spiral-lab.example", "spiral-research", bind, [7; 32]).unwrap(),
        )
        .unwrap();
        Script {
            ch,
            sh: None,
            sent: Vec::new(),
            pool: pool.clone(),
            bad_finished: None,
            bad_ct: false,
            bind,
            end: Instant::now() + Duration::from_secs(5),
        }
    }
    #[tokio::test]
    async fn finished_each_byte_and_changed_ct_rejected() {
        let pool = KemPool::new(2).unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        for i in 0..32 {
            let mut io = script(&pool);
            io.bad_finished = Some(i);
            assert!(server_inner(
                &mut io,
                "spiral-lab.example",
                "spiral-research",
                &key,
                &pool
            )
            .await
            .is_err());
            assert_eq!(io.sent, vec![2]);
            assert_eq!(pool.metrics().live_keys, 0);
        }
        let mut io = script(&pool);
        io.bad_ct = true;
        assert!(server_inner(
            &mut io,
            "spiral-lab.example",
            "spiral-research",
            &key,
            &pool
        )
        .await
        .is_err());
        assert_eq!(io.sent, vec![2]);
        pool.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn valid_server_state_and_exporter_mismatch() {
        let pool = KemPool::new(2).unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        let mut io = script(&pool);
        let (_, id) = server_inner(
            &mut io,
            "spiral-lab.example",
            "spiral-research",
            &key,
            &pool,
        )
        .await
        .unwrap();
        assert_eq!(io.sent, vec![2, 4]);
        drop(id);
        let mut io = script(&pool);
        io.bind[0] ^= 1;
        assert!(server_inner(
            &mut io,
            "spiral-lab.example",
            "spiral-research",
            &key,
            &pool
        )
        .await
        .is_err());
        assert!(io.sent.is_empty());
        pool.shutdown().await.unwrap();
    }
}
