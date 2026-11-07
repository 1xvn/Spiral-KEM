#![forbid(unsafe_code)]
use crate::buffer::Buffer;
use zeroize::Zeroize;

/// Heap-stable, unique owner. No Copy, Clone or contents-displaying Debug.
pub struct Secret<const N: usize> {
    storage: Box<[u8; N]>,
    #[cfg(test)]
    wipe_witness: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}
impl<const N: usize> Secret<N> {
    pub(crate) fn zeros() -> Self {
        Self {
            storage: Box::new([0; N]),
            #[cfg(test)]
            wipe_witness: None,
        }
    }
    pub(crate) fn bytes(&self) -> &[u8; N] {
        &self.storage
    }
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.storage
    }
    #[cfg(test)]
    pub(crate) fn watch_wipe(&mut self, witness: std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        self.wipe_witness = Some(witness);
    }
}
impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.storage.as_mut().zeroize();
        #[cfg(test)]
        if let Some(witness) = &self.wipe_witness {
            // Observe initialized, still-owned bytes before the Box is freed.
            // Only a zero/nonzero result is retained; never record secret bytes.
            witness.store(
                if self.storage.iter().all(|b| *b == 0) {
                    1
                } else {
                    2
                },
                std::sync::atomic::Ordering::SeqCst,
            );
        }
    }
}

/// Owns authenticated plaintext; buffers are overwritten before returning to the pool.
pub struct Plaintext {
    pub(crate) buffer: Buffer,
    pub(crate) start: usize,
    pub(crate) length: usize,
}
impl Plaintext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer.data[self.start..self.start + self.length]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    fn tracked() -> (Secret<32>, Arc<AtomicUsize>) {
        let witness = Arc::new(AtomicUsize::new(0));
        let mut key = Secret::zeros();
        key.bytes_mut().fill(0xa5);
        key.watch_wipe(witness.clone());
        (key, witness)
    }
    #[test]
    fn owned_secret_is_zero_before_free_on_normal_and_error_exit() {
        let (key, witness) = tracked();
        assert_eq!(witness.load(Ordering::SeqCst), 0);
        drop(key);
        assert_eq!(witness.load(Ordering::SeqCst), 1);
        let (key, witness) = tracked();
        fn fail(_key: Secret<32>) -> crate::Result<()> {
            Err(crate::Error::Crypto)
        }
        assert!(fail(key).is_err());
        assert_eq!(witness.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn owned_secret_is_zero_before_free_on_panic_and_thread_exit() {
        let (key, witness) = tracked();
        assert!(std::thread::spawn(move || {
            let _held = key;
            panic!("injected panic");
        })
        .join()
        .is_err());
        assert_eq!(witness.load(Ordering::SeqCst), 1);
        let (key, witness) = tracked();
        std::thread::spawn(move || drop(key)).join().unwrap();
        assert_eq!(witness.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn canceled_task_wipes_its_owned_secret() {
        let (key, witness) = tracked();
        let (send, recv) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _key = key;
            send.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        recv.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(witness.load(Ordering::SeqCst), 1);
    }
}
