use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;
struct OwnedBytes<T: AsMut<[u8]>>(T);
impl<T: AsMut<[u8]>> Drop for OwnedBytes<T> {
    fn drop(&mut self) { self.0.as_mut().zeroize(); }
}
fn main() {
    fn owned_state<T: zeroize::ZeroizeOnDrop>() {}
    owned_state::<Sha256>();
    owned_state::<Sha512>();
    fn scalar_contract<T: Copy + Clone + Zeroize>() {}
    scalar_contract::<curve25519_dalek::Scalar>();
    let _output_guard = OwnedBytes(Sha512::digest(b"public compile probe"));
    let _scalar_guard = zeroize::Zeroizing::new(curve25519_dalek::Scalar::from_bytes_mod_order([1; 32]));
    #[cfg(feature = "array-zeroize")]
    {
        fn output_is_zeroize<T: Zeroize>() {}
        output_is_zeroize::<hmac::digest::Output<hmac::Hmac<Sha256>>>();
        output_is_zeroize::<hmac::digest::Output<Sha512>>();
    }
}
