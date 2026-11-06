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
