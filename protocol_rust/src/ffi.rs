//! Only direct native KEM boundary. Keys cannot cross threads.
use crate::{secret::Secret, Error, Result};
use std::{
    ffi::{c_int, c_void},
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
};

unsafe extern "C" {
    fn sp_keygen(pk: *mut u8, key: *mut *mut c_void) -> c_int;
    fn sp_encaps(pk: *const u8, length: usize, ct: *mut u8, ss: *mut u8) -> c_int;
    fn sp_decaps_once(key: *mut c_void, ct: *const u8, length: usize, ss: *mut u8) -> c_int;
    fn sp_key_destroy(key: *mut *mut c_void);
}
fn status(code: c_int) -> Result<()> {
    match code {
        0 => Ok(()),
        1 => Err(Error::Input),
        2 => Err(Error::Crypto),
        3 => Err(Error::UsedKey),
        _ => Err(Error::Internal),
    }
}
pub(crate) struct NativeKey {
    pointer: NonNull<c_void>,
    _local: PhantomData<Rc<()>>,
}
impl NativeKey {
    pub(crate) fn generate() -> Result<(Box<[u8; 808]>, Self)> {
        let mut pk = Box::new([0; 808]);
        let mut pointer = std::ptr::null_mut();
        // SAFETY: distinct live buffers of the C profile sizes; key output starts NULL.
        status(unsafe { sp_keygen(pk.as_mut_ptr(), &mut pointer) })?;
        let pointer = NonNull::new(pointer).ok_or(Error::Internal)?;
        Ok((
            pk,
            Self {
                pointer,
                _local: PhantomData,
            },
        ))
    }
    pub(crate) fn decapsulate(self, ct: &[u8; 1160]) -> Result<Secret<32>> {
        let mut out = Secret::zeros();
        // SAFETY: unique live native key, immutable correctly sized ciphertext,
        // distinct mutable output. C does not retain either Rust pointer.
        status(unsafe {
            sp_decaps_once(
                self.pointer.as_ptr(),
                ct.as_ptr(),
                ct.len(),
                out.bytes_mut().as_mut_ptr(),
            )
        })?;
        Ok(out) // self Drop always releases the consumed native object.
    }
}
impl Drop for NativeKey {
    fn drop(&mut self) {
        let mut pointer = self.pointer.as_ptr();
        // SAFETY: called once by the worker-local unique owner after all C calls finish.
        unsafe { sp_key_destroy(&mut pointer) };
    }
}
pub(crate) fn encapsulate(pk: &[u8; 808]) -> Result<(Box<[u8; 1160]>, Secret<32>)> {
    let mut ct = Box::new([0; 1160]);
    let mut ss = Secret::zeros();
    // SAFETY: distinct live buffers with the exact ABI sizes; no retained pointers.
    status(unsafe {
        sp_encaps(
            pk.as_ptr(),
            pk.len(),
            ct.as_mut_ptr(),
            ss.bytes_mut().as_mut_ptr(),
        )
    })?;
    Ok((ct, ss))
}

#[cfg(test)]
mod ownership_contract {
    static_assertions::assert_not_impl_any!(super::NativeKey: Send,Sync,Clone,Copy);
    static_assertions::assert_not_impl_any!(crate::worker::KemLease: Clone,Copy);
    static_assertions::assert_not_impl_any!(crate::secret::Secret<32>: Clone,Copy);
    static_assertions::assert_not_impl_any!(crate::secret::Plaintext: Clone,Copy);
    static_assertions::assert_not_impl_any!(crate::handshake::Established: Clone,Copy);
}

// Valgrind client requests compiled only into Linux amd64/arm64 tests;
// normal binaries have neither client requests nor taint/fixed-seed entry points.
#[cfg(all(test, target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod taint_audit {
    use crate::{
        buffer::Pool,
        identity::ServerIdentity,
        records::Tx,
        schedule,
        secret::{Plaintext, Secret},
    };

    use crate::valgrind_audit::{require_valgrind, mark_public as public, mark_secret};
    fn secret(bytes: &mut [u8]) {
        let mode = std::env::var("SPIRAL_DERIVATION_TAINT").unwrap_or_else(|_| "secret".into());
        assert!(mode == "secret" || mode == "public");
        if mode == "secret" { mark_secret(bytes); }
    }

    #[test]
    #[ignore = "positive control: must produce Memcheck exit code 99"]
    fn positive_control() {
        require_valgrind();
        let mut bit = [1u8];
        mark_secret(&mut bit);
        if std::hint::black_box(bit[0]) != 0 {
            std::hint::black_box(1);
        }
        public(&mut bit);
    }

    #[test]
    #[ignore = "run optimized test executable under Valgrind; no TLS or C in this scope"]
    fn rust_secret_derivation_sealing_and_signing() {
        require_valgrind();
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../protocol_v01/tests/fixtures/test_vectors_v0.1.json"
        ))
        .unwrap();
        let frame = |name: &str| hex::decode(v["frames"][name].as_str().unwrap()).unwrap();
        let (ch, sh, ck, sf) = (
            frame("client_hello"),
            frame("server_hello"),
            frame("client_key"),
            frame("server_finished"),
        );
        let mut ss = Secret::<32>::zeros();
        ss.bytes_mut().fill(7);
        secret(ss.bytes_mut());
        let mut s = schedule::schedule(&ch, &sh, &ck[..40], &ck[40..1200], ss).unwrap();
        // Only transmitted Finished/MAC/ciphertext/public-key/signature outputs
        // are declassified. PRKs, derived keys and signing seeds stay tainted.
        public(&mut s.cf);
        let mut finished = schedule::mac(s.sf.bytes(), &[b"public transcript"]);
        public(&mut finished);
        let keys = schedule::finish(s, [1; 16], &ch, &sh, &ck, &sf).unwrap();
        for (key, prefix, role) in [(keys.c, keys.cp, 0), (keys.s, keys.sp, 1)] {
            let mut tx = Tx::new(key, prefix, [1; 16], role).unwrap();
            let pool = Pool::new();
            for length in [1, 16, 63, 64, 65, 1024, 16384] {
                let mut buffer = pool.take().unwrap();
                buffer.data.resize(length, 0x55);
                secret(&mut buffer.data);
                let mut wire = tx
                    .data(Plaintext {
                        buffer,
                        start: 0,
                        length,
                    })
                    .unwrap();
                public(&mut wire.data);
                assert_eq!(wire.data.len(), 40 + length + 16);
            }
            let mut close = tx.close(0).unwrap();
            public(&mut close);
        }
        let mut seed = [7; 32];
        secret(&mut seed);
        let identity = ServerIdentity::fixture(&seed);
        let mut key = identity.public_key();
        public(&mut key);
        for message in [b"".as_slice(), b"public transcript", sh.as_slice()] {
            let mut signature = identity.sign(message).unwrap().to_bytes();
            public(&mut signature);
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .unwrap()
                .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
                .unwrap();
        }
        identity.close().unwrap();
        public(&mut seed);
        println!("DERIVATION_AUDIT_COMPLETED");
    }
}
