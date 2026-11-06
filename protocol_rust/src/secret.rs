#![forbid(unsafe_code)]
use crate::buffer::Buffer;
use zeroize::Zeroize;

/// Heap-stable, unique owner. No Copy, Clone or contents-displaying Debug.
pub struct Secret<const N: usize>(Box<[u8; N]>);
impl<const N: usize> Secret<N> {
    pub(crate) fn zeros() -> Self {
        Self(Box::new([0; N]))
    }
    pub(crate) fn bytes(&self) -> &[u8; N] {
        &self.0
    }
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}
impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.as_mut().zeroize();
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
