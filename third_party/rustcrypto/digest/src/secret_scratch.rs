//! Private owner of named byte scratch; historical copies/registers are out of scope.
use core::ops::{Deref, DerefMut};

#[derive(Clone)]
pub(crate) struct SecretBytes<T: AsMut<[u8]>>(T);

impl<T: AsMut<[u8]>> SecretBytes<T> {
    #[inline]
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }
}
impl<T: AsMut<[u8]>> Deref for SecretBytes<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: AsMut<[u8]>> DerefMut for SecretBytes<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T: AsMut<[u8]>> Drop for SecretBytes<T> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(self.0.as_mut());
    }
}

#[cfg(all(test, feature = "zeroize"))]
mod tests {
    extern crate std;
    use super::SecretBytes;
    use core::cell::Cell;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    struct Witness<'a> {
        bytes: [u8; 32],
        observed: &'a Cell<bool>,
    }
    impl AsMut<[u8]> for Witness<'_> {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.bytes
        }
    }
    impl Drop for Witness<'_> {
        fn drop(&mut self) {
            // The value is still owned and initialized; never inspect freed memory.
            self.observed.set(self.bytes.iter().all(|byte| *byte == 0));
        }
    }
    #[test]
    fn wipes_owned_bytes_before_value_drop_on_return_and_error() {
        fn run(observed: &Cell<bool>, fail: bool) -> Result<(), ()> {
            let _owned = SecretBytes::new(Witness {
                bytes: [0xa5; 32],
                observed,
            });
            if fail {
                return Err(());
            }
            Ok(())
        }
        for fail in [false, true] {
            let observed = Cell::new(false);
            assert_eq!(run(&observed, fail).is_err(), fail);
            assert!(observed.get());
        }
    }
    #[test]
    fn wipes_owned_bytes_before_value_drop_on_unwind() {
        let observed = Cell::new(false);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _owned = SecretBytes::new(Witness {
                bytes: [0xa5; 32],
                observed: &observed,
            });
            panic!("injected scratch-owner unwind");
        }));
        assert!(result.is_err());
        assert!(observed.get());
    }
}
