//! Private cleanup of the named hash output used by scalar reduction.
//! Backend limbs, moved copies and registers are outside this slot's contract.
use core::ops::Deref;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub(crate) struct SecretBytes<T: AsMut<[u8]>>(T);
impl<T: AsMut<[u8]>> SecretBytes<T> {
    #[inline]
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }
}
impl<T: AsMut<[u8]>> Deref for SecretBytes<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: AsMut<[u8]>> Drop for SecretBytes<T> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.0.as_mut().zeroize();
    }
}

#[cfg(all(test, feature = "zeroize"))]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};
    struct ObservedBytes([u8; 64], Rc<Cell<bool>>);
    impl AsMut<[u8]> for ObservedBytes {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }
    impl Drop for ObservedBytes {
        fn drop(&mut self) {
            self.1.set(self.0.iter().all(|b| *b == 0));
        }
    }
    #[test]
    fn hash_output_is_zero_before_inner_drop_on_return_and_unwind() {
        for unwind in [false, true] {
            let observed = Rc::new(Cell::new(false));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _output = SecretBytes::new(ObservedBytes([0xA5; 64], observed.clone()));
                if unwind {
                    panic!("injected hash output unwind");
                }
            }));
            assert_eq!(result.is_err(), unwind);
            assert!(observed.get());
        }
    }
}
