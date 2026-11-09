//! Opaque, revocable owner of the server authentication key.
#![forbid(unsafe_code)]
use crate::{secret::Secret, Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey};
use std::{
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
};

/// Server authentication capability. Only its public key can be exported.
///
/// Sharing an `Arc<ServerIdentity>` shares this owner, not the key bytes.
/// `close()` revokes every shared reference and waits for an in-flight signature.
/// The final owner also drops the key. This is a same-process API boundary.
/// ```compile_fail
/// # use spiral_protocol::identity::ServerIdentity;
/// fn export(key: &ServerIdentity) { let _ = key.to_bytes(); }
/// ```
/// ```compile_fail
/// # use spiral_protocol::identity::ServerIdentity;
/// fn sign_arbitrary(key: &ServerIdentity) { let _ = key.sign(b"outside handshake"); }
/// ```
/// ```compile_fail
/// # use spiral_protocol::identity::ServerIdentity;
/// fn expose(key: &ServerIdentity) { let _ = &key.signing; }
/// ```
pub struct ServerIdentity {
    signing: Mutex<Option<SigningKey>>,
    public: [u8; 32],
}
impl ServerIdentity {
    /// Load one 32-byte seed through the protected Linux private-file boundary.
    pub fn load(path: &Path) -> Result<Arc<Self>> {
        Self::read_seed(crate::keyfiles::open_private(path)?)
    }
    /// Generate an OS-random seed in a new private file, never replacing a key.
    /// Only the public key is returned. File policy and durability errors fail closed.
    /// A directory-sync error after atomic publication can leave the final file
    /// present. Inspect it explicitly; never assume an error permits replacement.
    pub fn generate(path: &Path) -> Result<[u8; 32]> {
        let mut seed = Secret::<32>::zeros();
        getrandom::getrandom(seed.bytes_mut()).map_err(|_| Error::Crypto)?;
        let public = SigningKey::from_bytes(seed.bytes())
            .verifying_key()
            .to_bytes();
        crate::keyfiles::write_new_private(path, seed.bytes())?;
        Ok(public)
    }
    fn read_seed(mut reader: impl Read) -> Result<Arc<Self>> {
        let mut seed = Secret::<32>::zeros();
        reader.read_exact(seed.bytes_mut())?;
        let mut extra = zeroize::Zeroizing::new([0; 1]);
        if reader.read(extra.as_mut())? != 0 {
            return Err(Error::Input);
        }
        drop(extra);
        let key = SigningKey::from_bytes(seed.bytes());
        drop(seed);
        let public = key.verifying_key().to_bytes();
        Ok(Arc::new(Self {
            signing: Mutex::new(Some(key)),
            public,
        }))
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Idempotent revocation. A poisoned owner is erased as well, then rejected.
    pub fn close(&self) -> Result<()> {
        match self.signing.lock() {
            Ok(mut state) => {
                drop(state.take());
                Ok(())
            }
            Err(poisoned) => {
                drop(poisoned.into_inner().take());
                Err(Error::Internal)
            }
        }
    }
    pub fn is_closed(&self) -> Result<bool> {
        Ok(self.signing.lock().map_err(|_| Error::Internal)?.is_none())
    }
    pub(crate) fn sign(&self, message: &[u8]) -> Result<Signature> {
        let state = self.signing.lock().map_err(|_| Error::Internal)?;
        state
            .as_ref()
            .ok_or(Error::Closed)?
            .try_sign(message)
            .map_err(|_| Error::Crypto)
    }
    #[cfg(test)]
    pub(crate) fn fixture(seed: &[u8; 32]) -> Arc<Self> {
        Self::read_seed(seed.as_slice()).unwrap()
    }
}
impl Drop for ServerIdentity {
    fn drop(&mut self) {
        let state = self.signing.get_mut().unwrap_or_else(|e| e.into_inner());
        drop(state.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;
    use std::sync::Barrier;
    static_assertions::assert_not_impl_any!(ServerIdentity: Clone,Copy,std::fmt::Debug);
    static_assertions::assert_impl_all!(ServerIdentity: Send,Sync);

    #[test]
    fn seed_length_and_io_failure_are_rejected() {
        for length in [0, 1, 31, 33, 64] {
            assert!(ServerIdentity::read_seed(vec![42; length].as_slice()).is_err());
        }
        struct Fault;
        impl Read for Fault {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected read failure"))
            }
        }
        assert!(ServerIdentity::read_seed(Fault).is_err());
    }
    #[test]
    fn shared_references_are_revoked_and_double_close_is_safe() {
        let owner = ServerIdentity::fixture(&[42; 32]);
        let shared = owner.clone();
        let public = VerifyingKey::from_bytes(&owner.public_key()).unwrap();
        public
            .verify_strict(b"transcript", &shared.sign(b"transcript").unwrap())
            .unwrap();
        owner.close().unwrap();
        owner.close().unwrap();
        assert!(shared.is_closed().unwrap());
        assert!(matches!(shared.sign(b"transcript"), Err(Error::Closed)));
        assert_eq!(shared.public_key(), public.to_bytes());
    }
    #[test]
    fn concurrent_signers_cannot_reopen_a_revoked_owner() {
        let owner = ServerIdentity::fixture(&[43; 32]);
        let public = VerifyingKey::from_bytes(&owner.public_key()).unwrap();
        let barrier = Arc::new(Barrier::new(9));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let key = owner.clone();
            let start = barrier.clone();
            threads.push(std::thread::spawn(move || {
                start.wait();
                for _ in 0..32 {
                    match key.sign(b"public test transcript") {
                        Ok(sig) => public
                            .verify_strict(b"public test transcript", &sig)
                            .unwrap(),
                        Err(Error::Closed) => break,
                        Err(e) => panic!("unexpected {e:?}"),
                    }
                }
            }));
        }
        barrier.wait();
        owner.close().unwrap();
        for thread in threads {
            thread.join().unwrap();
        }
        for _ in 0..32 {
            assert!(matches!(owner.sign(b"after close"), Err(Error::Closed)));
        }
    }
    #[test]
    fn close_waits_for_the_active_key_borrow() {
        let owner = ServerIdentity::fixture(&[44; 32]);
        let guard = owner.signing.lock().unwrap();
        let shared = owner.clone();
        let (send, recv) = std::sync::mpsc::channel();
        let job = std::thread::spawn(move || {
            shared.close().unwrap();
            send.send(()).unwrap();
        });
        assert!(recv
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err());
        assert!(guard.is_some());
        drop(guard);
        recv.recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        job.join().unwrap();
        assert!(owner.is_closed().unwrap());
    }
    #[test]
    fn poisoned_owner_is_erased_and_remains_unusable() {
        let owner = ServerIdentity::fixture(&[45; 32]);
        let shared = owner.clone();
        assert!(std::thread::spawn(move || {
            let _guard = shared.signing.lock().unwrap();
            panic!("injected panic");
        })
        .join()
        .is_err());
        assert!(matches!(owner.close(), Err(Error::Internal)));
        assert!(owner.signing.lock().unwrap_err().into_inner().is_none());
        assert!(matches!(owner.sign(b"after panic"), Err(Error::Internal)));
    }
}
