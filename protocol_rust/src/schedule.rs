#![forbid(unsafe_code)]
use crate::{secret::Secret, Error, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;
pub const PID: &[u8] = b"SpiralOPT2-Proto-v0.1";
pub fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
pub fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
pub fn domain(label: &[u8]) -> Vec<u8> {
    let mut v = PID.to_vec();
    v.push(0);
    v.extend_from_slice(&(label.len() as u16).to_be_bytes());
    v.extend_from_slice(label);
    v
}
pub fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}
pub fn expand<const N: usize>(root: &[u8], label: &[u8], h: &[u8; 32]) -> Result<Secret<N>> {
    if N == 0 || N > 32 || label.len() > u16::MAX as usize {
        return Err(Error::Input);
    }
    let mut info = Vec::new();
    info.extend_from_slice(&(PID.len() as u16).to_be_bytes());
    info.extend_from_slice(PID);
    info.extend_from_slice(&1u16.to_be_bytes());
    info.extend_from_slice(&0xf001u16.to_be_bytes());
    info.extend_from_slice(&(label.len() as u16).to_be_bytes());
    info.extend_from_slice(label);
    info.extend_from_slice(&(N as u16).to_be_bytes());
    info.extend_from_slice(h);
    let mut out = Secret::zeros();
    hkdf::Hkdf::<Sha256>::from_prk(root)
        .map_err(|_| Error::Crypto)?
        .expand(&info, out.bytes_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}
pub struct Schedule {
    pub(crate) prk: Secret<32>,
    pub(crate) sf: Secret<32>,
    pub cf: [u8; 32],
}
pub fn schedule(
    ch: &[u8],
    sh: &[u8],
    ck_header: &[u8],
    ct: &[u8],
    ss: Secret<32>,
) -> Result<Schedule> {
    let h = hash_parts(&[ch, sh, ck_header, ct]);
    let (mut raw, _) = hkdf::Hkdf::<Sha256>::extract(Some(&h), ss.bytes());
    let mut prk = Secret::zeros();
    prk.bytes_mut().copy_from_slice(&raw);
    raw.as_mut_slice().zeroize();
    drop(ss);
    let cf_key = expand::<32>(prk.bytes(), b"client-finished", &h)?;
    let sf = expand::<32>(prk.bytes(), b"server-finished", &h)?;
    let cf = mac(cf_key.bytes(), &[&domain(b"client-finished"), &h]);
    Ok(Schedule { prk, sf, cf })
}
pub struct SessionKeys {
    pub sid: [u8; 16],
    pub(crate) c: Secret<32>,
    pub(crate) s: Secret<32>,
    pub(crate) cp: [u8; 4],
    pub(crate) sp: [u8; 4],
    pub transcript: [u8; 32],
}
pub fn finish(
    s: Schedule,
    sid: [u8; 16],
    ch: &[u8],
    sh: &[u8],
    ck: &[u8],
    sf: &[u8],
) -> Result<SessionKeys> {
    let h = hash_parts(&[ch, sh, ck, sf]);
    let master = expand::<32>(s.prk.bytes(), b"application-master", &h)?;
    let c = expand::<32>(master.bytes(), b"client-data-key", &h)?;
    let sk = expand::<32>(master.bytes(), b"server-data-key", &h)?;
    let cp = *expand::<4>(master.bytes(), b"client-nonce-prefix", &h)?.bytes();
    let sp = *expand::<4>(master.bytes(), b"server-nonce-prefix", &h)?.bytes();
    Ok(SessionKeys {
        sid,
        c,
        s: sk,
        cp,
        sp,
        transcript: h,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_key_schedule_vector() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../protocol_v01/tests/fixtures/test_vectors_v0.1.json"
        ))
        .unwrap();
        let f = |n: &str| hex::decode(v["frames"][n].as_str().unwrap()).unwrap();
        let e = |n: &str| hex::decode(v["expected"][n].as_str().unwrap()).unwrap();
        let (ch, sh, ck, sf) = (
            f("client_hello"),
            f("server_hello"),
            f("client_key"),
            f("server_finished"),
        );
        let mut ss = Secret::zeros();
        ss.bytes_mut().copy_from_slice(&e("shared_secret"));
        let s = schedule(&ch, &sh, &ck[..40], &ck[40..1200], ss).unwrap();
        assert_eq!(s.prk.bytes().as_slice(), e("handshake_prk"));
        assert_eq!(s.sf.bytes().as_slice(), e("server_finished_key"));
        assert_eq!(s.cf.as_slice(), e("client_finished"));
        let h0 = hash_parts(&[&ch, &sh, &ck[..1200]]);
        assert_eq!(h0.as_slice(), e("h0"));
        assert_eq!(
            expand::<32>(s.prk.bytes(), b"client-finished", &h0)
                .unwrap()
                .bytes()
                .as_slice(),
            e("client_finished_key")
        );
        let h1 = hash_parts(&[&ch, &sh, &ck, &sf[..40]]);
        assert_eq!(h1.as_slice(), e("h1"));
        assert_eq!(
            mac(s.sf.bytes(), &[&domain(b"server-finished"), &h1]).as_slice(),
            e("server_finished")
        );
        let sid = hex::decode(v["public"]["session_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let k = finish(s, sid, &ch, &sh, &ck, &sf).unwrap();
        assert_eq!(k.c.bytes().as_slice(), e("client_data_key"));
        assert_eq!(k.s.bytes().as_slice(), e("server_data_key"));
        assert_eq!(k.cp.as_slice(), e("client_nonce_prefix"));
        assert_eq!(k.sp.as_slice(), e("server_nonce_prefix"));
        assert_eq!(k.transcript.as_slice(), e("h2"));
    }
}
