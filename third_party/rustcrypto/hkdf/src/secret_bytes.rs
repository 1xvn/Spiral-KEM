//! Private ownership of named temporary outputs, not historical copies.
use core::ops::Deref;

pub(crate) struct SecretBytes<T: AsMut<[u8]>>(Option<T>);

impl<T: AsMut<[u8]>> SecretBytes<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(Some(value))
    }

    /// Transfer an output to its caller without erasing the returned value.
    pub(crate) fn into_inner(mut self) -> T {
        self.0.take().expect("owned output is present")
    }
}

impl<T: AsMut<[u8]>> Deref for SecretBytes<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("owned output is present")
    }
}

impl<T: AsMut<[u8]>> Drop for SecretBytes<T> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        if let Some(value) = self.0.as_mut() {
            let bytes = value.as_mut();
            zeroize::Zeroize::zeroize(bytes);
            #[cfg(test)]
            tests::record(bytes);
        }
    }
}

#[cfg(all(test, feature = "zeroize"))]
pub(crate) mod tests {
    extern crate std;
    use super::SecretBytes;
    use core::cell::{Cell, RefCell};
    use std::{panic::AssertUnwindSafe, vec::Vec};

    std::thread_local! {
        static OBSERVATIONS: RefCell<Vec<(usize, bool)>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(bytes: &[u8]) {
        // Inspect only a live, still-owned output and retain no secret bytes.
        OBSERVATIONS.with_borrow_mut(|rows| rows.push((bytes.len(), bytes.iter().all(|b| *b == 0))));
    }

    pub(crate) fn take() -> Vec<(usize, bool)> {
        OBSERVATIONS.with_borrow_mut(core::mem::take)
    }

    struct Witness<'a> {
        bytes: [u8; 16],
        erased: &'a Cell<bool>,
    }

    impl AsMut<[u8]> for Witness<'_> {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.bytes
        }
    }

    impl Drop for Witness<'_> {
        fn drop(&mut self) {
            self.erased.set(self.bytes.iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn guard_erases_before_the_owned_value_drops_normally_and_on_unwind() {
        let normal = Cell::new(false);
        drop(SecretBytes::new(Witness {
            bytes: [0xa5; 16],
            erased: &normal,
        }));
        assert!(normal.get());

        let unwind = Cell::new(false);
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = SecretBytes::new(Witness {
                bytes: [0xa5; 16],
                erased: &unwind,
            });
            panic!("injected generic operation panic");
        }));
        assert!(result.is_err());
        assert!(unwind.get());
    }

    #[test]
    fn transfer_preserves_the_returned_output() {
        let value = SecretBytes::new([0xa5; 32]).into_inner();
        assert_eq!(value, [0xa5; 32]);
    }
}
