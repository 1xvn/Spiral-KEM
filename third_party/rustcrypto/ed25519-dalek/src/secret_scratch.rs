//! Private, feature-gated cleanup of named signing scratch slots.
//!
//! This does not erase prior moves, scalar backend scratch, or registers.

use core::ops::{Deref, DerefMut};
use curve25519_dalek::Scalar;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Own an output without requiring `Array: Zeroize` through feature unification.
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
impl<T: AsMut<[u8]>> DerefMut for SecretBytes<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T: AsMut<[u8]>> Drop for SecretBytes<T> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.0.as_mut().zeroize();
    }
}

/// Keep Scalar's public Copy/Clone contract while cleaning this private owner.
pub(crate) struct SecretScalar(Scalar);
impl SecretScalar {
    #[inline]
    pub(crate) fn new(value: Scalar) -> Self {
        Self(value)
    }
}
impl Deref for SecretScalar {
    type Target = Scalar;
    fn deref(&self) -> &Scalar {
        &self.0
    }
}
impl Drop for SecretScalar {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.0.zeroize();
            #[cfg(test)]
            SCALAR_WIPES.with(|witness| {
                let (count, all_zero) = witness.get();
                witness.set((count + 1, all_zero && self.0.as_bytes().iter().all(|b| *b == 0)));
            });
        }
    }
}

#[cfg(all(test, feature = "zeroize"))]
std::thread_local! {
    static SCALAR_WIPES: core::cell::Cell<(usize, bool)> = const { core::cell::Cell::new((0, true)) };
}
#[cfg(all(test, feature = "zeroize"))]
pub(crate) fn reset_scalar_witness() {
    SCALAR_WIPES.with(|witness| witness.set((0, true)));
}
#[cfg(all(test, feature = "zeroize"))]
pub(crate) fn scalar_witness() -> (usize, bool) {
    SCALAR_WIPES.with(core::cell::Cell::get)
}

#[cfg(all(test, feature = "zeroize"))]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    struct ObservedBytes {
        bytes: [u8; 64],
        observed: Rc<Cell<bool>>,
    }
    impl AsMut<[u8]> for ObservedBytes {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.bytes
        }
    }
    impl Drop for ObservedBytes {
        fn drop(&mut self) {
            // The inner field is still alive here; no freed-memory inspection.
            self.observed.set(self.bytes.iter().all(|b| *b == 0));
        }
    }
    #[test]
    fn named_bytes_are_zero_before_inner_drop_on_return_and_unwind() {
        for unwind in [false, true] {
            let observed = Rc::new(Cell::new(false));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _owned = SecretBytes::new(ObservedBytes {
                    bytes: [0xA5; 64],
                    observed: observed.clone(),
                });
                if unwind {
                    panic!("injected scratch unwind");
                }
            }));
            assert_eq!(result.is_err(), unwind);
            assert!(observed.get());
        }
    }
}
